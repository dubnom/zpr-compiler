# ZPL Compiler

Can translate simple ZPL into binary policies that the prototype visa
service can process.  This comes bundled with a tool to examine the
contents of a "compiled" binary policy, `zpdump`.

Class definitions may omit `with`, but a written `with` clause must contain
at least one attribute. `define FooBar as a user with.` is a syntax error.

Defined class names receive an automatic English plural alias through the
`pluralizer` crate. For example, `define mouse as a user with id.` can be
referenced as `mice` in a permission. Attribute multiplicity is separate:
trusted-service mappings use `{}` (for example, `user.role{}`) to mark a
multi-valued attribute.

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

## Advisory Lint

```sh
./zplc --parse-only --lint -c path/to/config.zplc path/to/policy.zpl
```

`--lint` examines the parsed policy and emits `ZPR_LINT` JSON diagnostics with
code, severity, source line and message. It reports individual accessor identity
selectors (including inherited classes), equivalent duplicate rules,
conservative redundant grants, unrestricted grants, and service groups with no
access rules. User/group roles and department/posture predicates are preferred;
provider identity bindings for a declared service are not accessor warnings.

Infrastructure-specific device selectors can be intentional. Lint does not
rewrite policy, affect signed output, or change compilation exit status.
Existing compiler warnings retain their separate `--Werror` behavior. Redundancy
analysis compares parsed accessor conjunctions with the same target, link and
signal behavior; it is not a general policy equivalence or satisfiability solver.


## How to build

- `make`



## TODO

Work is ongoing to accept the full ZPL syntax. Note that it is one
thing for the compiler to accept the syntax and process it into a policy
and another for the Visa Service to be able to implement the policy.

Here are syntax bits that are not yet supported by the compiler:

- Limits.
- Conditions.



