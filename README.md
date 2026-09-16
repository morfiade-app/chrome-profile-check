# chrome-profile-check

**Find out what is actually inside your Chrome profiles — and what a plain copy
will lose — before you copy anything.**

Copying a profile folder to another computer looks like it works. The size
matches, every file is there. Then you open it and you are logged out of
everything, the passwords are blank, and nothing explains why.

This script explains why in advance. It is a diagnostic, not a transfer tool.

```
pip install chrome-profile-check
chrome-profile-check
```

Python 3.7+, standard library only, no dependencies. Windows, macOS and Linux
paths are detected; the interesting failure is a Windows one.

## What it tells you

```
========================================================================
C:\Users\you\AppData\Local\Google\Chrome\User Data
  cookie key:      App-Bound (v20) present - cookies are tied to this Windows account
========================================================================

  Work   (Default)
    size          3.3 GB total, of which 2.1 GB is cache you never need to move
    worth moving  1.1 GB
    cookies       412
    saved logins  69
    bookmarks     229
    extensions    30
      v20 (App-Bound, tied to this Windows account) 412 cookies

  Shop   (Profile 2)
    size          379 MB total, of which 217 MB is cache you never need to move
    worth moving  162 MB
    cookies       22
    saved logins  1
    bookmarks     3
    extensions    4
      v20 (App-Bound, tied to this Windows account) 22 cookies

------------------------------------------------------------------------
WHAT A PLAIN FOLDER COPY LOSES
------------------------------------------------------------------------
  434 cookies use App-Bound encryption (v20). They are bound to this
  Windows account: copied to another machine - or to another account on
  this one - they decrypt to nothing, and every site asks you to log in
  again. This is Chrome's own protection, not a bug in your copy.
  ...
```

Four things worth knowing come out of that:

- **how much of the folder is cache.** Usually more than half. People copy
  gigabytes of cache across a network and wonder why it takes all evening;
- **how many cookies, logins, bookmarks and extensions** each profile really
  holds — useful when you are deciding which profiles are worth keeping;
- **which key protects the cookies.** `v10`/`v11` means the older machine key;
  `v20` means App-Bound Encryption, introduced in Chrome 127, which ties the
  value to one Windows account;
- **what survives a copy and what does not**, stated plainly at the end.

## What it never does

This matters more than the feature list, because the file it reads is the most
sensitive one on your disk:

- **it never decrypts anything.** Not cookies, not passwords, not the key;
- **it never prints a value.** Only counts, sizes and the three-byte version tag
  in front of each cookie — the tag says which scheme encrypted the rest, and it
  is not content;
- **it never writes.** Databases are opened `mode=ro&immutable=1`, so sqlite
  takes no locks and a running Chrome is not disturbed. Worst case is a slightly
  stale count;
- **it sends nothing anywhere.** No network code in the file at all — read it,
  it is under 300 lines.

If a profile is in active use, some counts come back as
`unreadable (Chrome running?)`. That is the honest answer, not a workaround to
be found.

## Usage

```
chrome-profile-check                    # every Chrome profile found
chrome-profile-check --json             # machine-readable
chrome-profile-check --dir "D:\Profiles"  # a User Data directory elsewhere
```

Or without installing: `python chrome_profile_check.py`.

## The short version of the problem

Since Chrome 127 on Windows, cookie values are encrypted with a key that is
itself protected by App-Bound Encryption — bound to the Windows account that
created it. Copy the folder to a different machine, or to a different account on
the same machine, and the cookies decrypt to nothing. Sessions are gone; you log
in again everywhere.

What does survive: bookmarks, history, extensions, settings, autofill.
Passwords are stored under the same account-bound protection — Chrome's own
export to CSV is the supported way to move those.

So the honest summary: **a folder copy moves your settings, not your sessions.**
Anyone promising otherwise is describing an older Chrome, or something you
should not run on your machine.

## Why this exists

We build [Morfiade](https://morfiade.com/en/), a Chrome profile manager for
Windows, and this question comes up constantly: *why did my copied profile lose
everything?* The answer is the same whether or not you ever use our program, so
the answer is a separate, open tool.

## License

MIT — see [LICENSE](LICENSE). Русская версия — [README.ru.md](README.ru.md).
