# Scenario lints (`--check`)

`sipr --check -sf scenario.xml` compiles a scenario, prints its compiled
form and exits. Besides the compile diagnostics (unknown elements are
errors, unknown attributes and keywords are warnings), `--check` runs the
**lints**: checks for scenarios that load and run but do not do what they
say. They catch the traps SIPp users learn the hard way, the ones recorded in
§6 of the [SIPp compatibility surface](SIPP_COMPAT.md).

Lint findings are warnings. As with every warning under `--check`, any one
of them makes the check exit 1. A normal run does not lint, so the lints
cost a run nothing and print nothing there.

Each finding names its lint:

```text
sipr: uas.xml:15: warning[optional-window]: optional <recv request="INFO"> ends the scenario with no mandatory <recv> after it: …
```

## The lints

### `optional-window`

An optional `<recv>` only means something next to a mandatory one: when a
message arrives, the engine checks the run of optional recvs up to the next
mandatory recv (the *window*). An optional recv with no mandatory recv after
it still holds the call, exactly as a mandatory one would. The lint flags
two forms:

- **A `<send>`, `<pause>`, `<nop>`, `<sendCmd>` or `<timewait>` comes
  next.** SIPp refuses to load such a scenario (*"&lt;recv&gt; before
  &lt;send&gt; sequence without a mandatory message"*). sipr runs it, so
  without the lint the scenario would only fail once it was taken to SIPp.
- **The scenario ends with it and it has no `timeout`.** The call waits for
  that message. If it never comes, the call never ends and neither does a
  run with `-m`. Give the recv `timeout=` and `ontimeout=`, or end the
  scenario with a `<timewait>`, which absorbs late messages without waiting
  for one.

Labels between recvs do not break a window. A mandatory `<recvCmd>` anchors
one, as in SIPp.

### `unreachable`

A step that no path through the scenario reaches: it follows an
unconditional `next=` (no `test`, `chance` or `condexec`) and nothing jumps
to it, or it follows a `<timewait>`. SIPp refuses any step after a
`<timewait>`. One finding covers a whole run of dead steps, labels included.

The analysis is conservative. `ontimeout=`, `jump value=` and the
`_unexp.main` handler count as ways in, and so does the window behind an
optional recv. A `jump variable=` could land anywhere, so a scenario that
has one is not checked. The exception is the `_unexp.retaddr` return, which
goes back to a step that already ran.

A jump counts where SIPp lands it. SIPp sets `msg_index = N - 1` and runs
`next()`, so a jump to message N lands on the `next=` of message N-1 when
it has one, and on N only when that `next=` has a `test` or `chance`, or
when there is none. A jump in a recv's actions counts only when the recv
is optional and has a `next=` with a `test=`, which can make it stay where
the call waited. The call then waits at message N-1. Any other recv, and
every `<recvCmd>`, moves on through `next()`, which overwrites the jump.

### `body-separator`

A line that looks like SDP (`v=0`, `o=…`, `m=audio …`) sits among the
headers, so the blank line that ends the headers is missing. The peer reads
the SDP lines as malformed headers, and `[len]` does not count them.

### `content-length`

A `Content-Length` (or compact `l:`) header that is, or may be, wrong:

- a literal number when the body holds keywords (`[local_ip]`,
  `[media_port]`, …), whose rendered length changes from call to call;
- a literal number that differs from the body's length. The length is in
  bytes on the wire, where lines end in CRLF, so a count taken with bare
  newlines comes out short;
- no Content-Length at all on a message with a body. Over UDP the datagram
  ends the message, but over TCP or TLS the peer cannot tell where it ends.

The fix in each case is `Content-Length: [len]`. A header whose value is
`[len]` or any other keyword renders at send time and is not checked.

## Silencing a finding

A test tool must be able to misbehave on purpose: a scenario that sends a
wrong Content-Length to see how a proxy copes should still pass `--check`.
Put a directive in a comment directly before the step:

```xml
<!-- sipr-lint: allow content-length -->
<send><![CDATA[
  INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
  ...
  Content-Length: 5
]]></send>
```

- A directive silences the named lints for **the next step only**. Names
  may be separated by commas or spaces, and consecutive directives add up.
- The directive must sit directly inside `<scenario>`, before a step
  element. Anywhere else (before `<scenario>`, inside a `<send>`, before
  `<Reference>`, or at the end with no step after it), `--check` warns that
  it has no effect.
- An unknown lint name or a malformed directive is a warning too, so a typo
  cannot silently keep a lint on.

SIPp ignores comments, so the directives do not change how SIPp runs the
scenario.
