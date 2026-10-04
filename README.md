# ZPL Compiler

Can translate simple ZPL into binary policies that the prototype visa
service can process.  This comes bundled with a tool to examine the
contents of a "compiled" binary policy, `zpdump`.

Class definitions may omit `with`, but a written `with` clause must contain
at least one attribute. `define FooBar as a user with.` is a syntax error.

## Example usage

```bash
./zplc -k path/to/rsa-key.pem path/to/policy.zpl
cargo run --bin zplfmt -- path/to/policy.zpl
```

`zplfmt` writes formatted ZPL to standard output. Consecutive blank lines are
condensed to one, including whitespace-only lines and trailing blank lines.
It indents `allow`, `deny`,
and `never` statements by two spaces, removes leading whitespace and blank lines
between consecutive definitions or within service permission groups, and
inserts a blank line before `provide` and
embedded `service` declarations when they follow a nonblank line, and adds a
blank line before the next `define` or service declaration after a permission
block. Comments, multiline statement content, and line endings are preserved.

- That RSA key in the invocation is used to sign the binary policy so
  must match the one that the visa service is configured with.
- By default the _configuration_ for the ZPL policy will be found in a
  file with the same name as the ZPL file but with the `zplc` extension.
  If you want to load configuration from somewhre else, use
  `-c path/to/config.zplc` argument.
- Help is available via `zplc -h`


## How to build

- `make`



## TODO

Work is ongoing to accept the full ZPL syntax. Note that it is one
thing for the compiler to accept the syntax and process it into a policy
and another for the Visa Service to be able to implement the policy.

Here are syntax bits that are not yet supported by the compiler:

- Limits.
- Conditions.



