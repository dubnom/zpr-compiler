use openssl::pkey::Private;
use openssl::rsa::Rsa;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config_api::ConfigApi;
use crate::context::CompilationCtx;
use crate::crypto::{sha256_of_file, sign_pkcs1v15_sha256};
use crate::errors::CompilationError;
use crate::lex::tokenize;
use crate::parser::parse;
use crate::policybinaryv2::{PolicyBinaryV2, PolicyContainerV2};
use crate::policybuilder::PolicyBuilder;
use crate::policywriter::PolicyContainer;
use crate::ptypes::{AllowClause, Policy};
use crate::weaver::weave;

/// Create one of these with the [CompilationBuilder].
pub struct Compilation {
    pub verbose: bool,
    werror: bool,
    lint: bool,
    pub source_zpl: PathBuf,
    pub source_config: PathBuf,
    pub output_file: PathBuf,
    pub parse_only: bool,
    copied_allow_statements: Option<Vec<String>>,
    copied_never_allow_statements: Option<Vec<String>>,
    private_key: Option<Rsa<Private>>,
    output_format: OutputFormat,
}

impl Compilation {
    /// Returns a new [CompilationBuilder] using the passed ZPL source file and
    /// reasonable defaults.
    pub fn builder(source: PathBuf) -> CompilationBuilder {
        CompilationBuilder::new(source)
    }

    pub fn zpl_for_allow_statement(&self, index: usize) -> String {
        self.zpl_for_statement(&self.copied_allow_statements, index)
    }

    pub fn zpl_for_never_allow_statement(&self, index: usize) -> String {
        self.zpl_for_statement(&self.copied_never_allow_statements, index)
    }

    fn zpl_for_statement(&self, statements: &Option<Vec<String>>, index: usize) -> String {
        if let Some(stmts) = statements {
            if index < stmts.len() {
                return stmts[index].clone();
            }
        }
        format!("no ZPL statement found at index {}", index)
    }

    /// Create/write a policy from the ZPL source and configuration.
    pub fn compile(&mut self) -> Result<(), CompilationError> {
        let cctx = CompilationCtx::new(self.verbose, self.werror);
        let pol = self.compile_to_policy(&cctx)?;
        cctx.info("build successful");
        if let Some(pol) = pol {
            let container_bytes = match self.output_format {
                OutputFormat::V2 => {
                    self.contain_policy(pol, &cctx, PolicyContainerV2::default())?
                }
                _ => {
                    return Err(CompilationError::FileError(format!(
                        "unsupported output format for policy container: {:?}",
                        self.output_format
                    )));
                }
            };
            self.write_container(&container_bytes, &self.output_file, &cctx)?;
        }
        Ok(())
    }

    /// Each allow or never-allow statement has a "span" with it that indicates where in the
    /// source ZPL file it is found.  We use that span here to copy out the statement text
    /// from the ZPL.  Statements are processed in order and assumed to be in file order.
    /// The n'th statement in the input list will correspond to the n'th string in the result.
    fn copy_permission_statements(
        &self,
        statements: &[AllowClause],
    ) -> Result<Vec<String>, CompilationError> {
        let mut zpl = Vec::new();

        let source = File::open(&self.source_zpl)?;
        let reader = io::BufReader::new(source);
        let mut lineno = 0;

        let mut stmt_itr = statements.iter();
        let cur_stmt = stmt_itr.next();
        if cur_stmt.is_none() {
            return Ok(zpl);
        }

        let mut cur_span = cur_stmt.unwrap().span.clone();
        let mut cur_chunk = String::new();

        for read_res in reader.lines() {
            let source_line = read_res?;
            lineno += 1;

            // We are either gathering chars until we get to the end
            // or skipping until we get to the start.  If cur_chunk is empty
            // we are looking for the start.

            if cur_chunk.is_empty() {
                if lineno < cur_span.0.line {
                    // Not yet at start so keep reading file.
                    continue;
                }
                // We are on the start line ... are we also on the ending line?
                if cur_span.1.line == lineno {
                    // Yes, the entire source for this statement is on this one line.
                    let first_col_idx = if (cur_span.0.col - 1) < source_line.len() {
                        0
                    } else {
                        cur_span.0.col - 1
                    };
                    let last_col_idx = if cur_span.1.col > source_line.len() {
                        source_line.len()
                    } else {
                        cur_span.1.col
                    };
                    cur_chunk.push_str(&source_line[first_col_idx..last_col_idx]);

                // And we are done with this span (fall through...)
                } else {
                    // The end position is further along in the file. So lets start with what we need on this line.
                    let first_col_idx = if (cur_span.0.col - 1) < source_line.len() {
                        0
                    } else {
                        cur_span.0.col - 1
                    };
                    cur_chunk.push_str(&source_line[first_col_idx..]);
                    continue;
                }
            } else {
                // We have data in our cur_chunk which means we are seeking the ending position.
                if lineno < cur_span.1.line {
                    // Can consume the entire line...
                    cur_chunk.push_str(" ");
                    cur_chunk.push_str(&source_line);
                    continue;
                } else {
                    // We are on the ending line (and by they way, ZPL statements always start on a new line).
                    let last_col_idx = if cur_span.1.col > source_line.len() {
                        source_line.len()
                    } else {
                        cur_span.1.col
                    };
                    cur_chunk.push_str(&source_line[..last_col_idx]);

                    // And we are done with current span (fall through...)
                }
            }

            // If we get here we are done with current span.
            zpl.push(cur_chunk);
            cur_chunk = String::new();
            if let Some(stmt) = stmt_itr.next() {
                cur_span = stmt.span.clone();
            } else {
                // We are at end of statements.
                break;
            }
        }
        if !cur_chunk.is_empty() {
            // Ran into a problem.. did not find the end of the last statement.
            return Err(CompilationError::FileError(format!(
                "ran out of file while copying ZPL permission statements"
            )));
        }
        if zpl.len() != statements.len() {
            return Err(CompilationError::FileError(format!(
                "did not find all permission statements in ZPL source (found {}, expected {})",
                zpl.len(),
                statements.len()
            )));
        }

        Ok(zpl)
    }

    /// Get and store the ZPL lines that correspond to the permission satements in policy.
    fn copy_zpl_from_permissions(&mut self, policy: &Policy) -> Result<(), CompilationError> {
        self.set_statement_zpl(false, &policy.allows)?;
        self.set_statement_zpl(true, &policy.nevers)?;
        Ok(())
    }

    /// Store the ZPL lines that correspond to the permission statements in policy.
    /// If the statements list is empty, clear any previously stored statements.
    /// This either updates the "allow" zpl or the "never allow" zpl depending on
    /// the `never` boolean.
    fn set_statement_zpl(
        &mut self,
        never: bool,
        statements: &[AllowClause],
    ) -> Result<(), CompilationError> {
        if !statements.is_empty() {
            let zpl = self.copy_permission_statements(statements)?;
            if never {
                self.copied_never_allow_statements = Some(zpl);
            } else {
                self.copied_allow_statements = Some(zpl);
            }
        } else {
            if never {
                self.copied_never_allow_statements = None;
            } else {
                self.copied_allow_statements = None;
            }
        }
        Ok(())
    }

    pub fn compile_to_policy(
        &mut self,
        cctx: &CompilationCtx,
    ) -> Result<Option<Vec<u8>>, CompilationError> {
        if self.verbose {
            println!(
                "compiling {:?} with config {:?}",
                self.source_zpl, self.source_config
            );
        }
        let cfg = ConfigApi::new_from_toml_file(&self.source_config, &cctx).map_err(|e| {
            CompilationError::ConfigError(format!(
                "failed to load configuration from {:?}: {}",
                self.source_config, e
            ))
        })?;

        let tz = tokenize(&self.source_zpl, &cctx)?;
        if self.verbose {
            println!("parsed {} tokens:", tz.tokens.len());
            for t in &tz.tokens {
                println!("   {:?}", t);
            }
            println!();
        }

        let pr = parse(tz.tokens, &cctx)?;
        let mut policy = pr.policy;

        if self.lint {
            for diagnostic in crate::lint::lint_policy(&policy) {
                println!(
                    "ZPR_LINT {}",
                    serde_json::to_string(&diagnostic).expect("lint diagnostic is serializable")
                );
            }
        }

        self.copy_zpl_from_permissions(&policy)?;

        let policy_digest = sha256_of_file(&self.source_zpl)?;
        policy.digest = Some(policy_digest);

        let fabric = weave(self, &cfg, &policy, &cctx)?;
        if self.verbose {
            println!();
            println!("fabric production:\n{}", fabric);
        }

        cctx.info("parse successful");
        if self.parse_only {
            return Ok(None);
        }

        let policy_bytes = match self.output_format {
            OutputFormat::V2 => {
                let writer = PolicyBinaryV2::new();
                let mut builder = PolicyBuilder::new(self.verbose, writer);
                builder.with_max_visa_lifetime(Duration::from_secs(60 * 60 * 12)); // 12 hours (TODO: Should come from config)
                builder.with_fabric(&fabric, &cctx)?;
                builder.build()?
            }
            _ => panic!("unsupported output format for policy binary"),
        };
        cctx.info("build successful");
        Ok(Some(policy_bytes))
    }

    /// Write the policy container to the output file, serializing with protocol buffers.
    fn write_container(
        &self,
        container: &[u8],
        file: &Path,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        std::fs::write(file, container).map_err(|e| {
            CompilationError::FileError(format!(
                "failed to write policy container to {:?}: {}",
                file, e
            ))
        })?;
        ctx.info(&format!("wrote {}", &file.display()));
        Ok(())
    }

    /// Create the container struct, move policy into it and optionally sign the policy with the private key.
    fn contain_policy<T>(
        &self,
        pol_buf: Vec<u8>,
        ctx: &CompilationCtx,
        container: T,
    ) -> Result<Vec<u8>, CompilationError>
    where
        T: PolicyContainer,
    {
        let signature = match self.private_key {
            Some(ref key) => {
                let sig = sign_pkcs1v15_sha256(key, &pol_buf)?;
                Some(sig)
            }
            None => {
                ctx.warn(
                    "policy not signed, use `--key <pemfile>` to specify a private key for signing",
                )?;
                None
            }
        };
        container.contain_policy(pol_buf, signature)
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    #[deprecated(since = "0.11.0", note = "use V2 instead")]
    V1, // Legacy format
    #[default]
    V2,
}

/// The entry point for the compilation process, this builder is used to configure
/// the various settings for the compiler.
#[derive(Default)]
pub struct CompilationBuilder {
    source_zpl: PathBuf,
    source_config: Option<PathBuf>,
    verbose: bool,
    werror: bool,
    lint: bool,
    private_key: Option<Rsa<Private>>,
    parse_only: bool,
    output_directory: Option<PathBuf>,
    out_filename: Option<String>,
    output_format: OutputFormat,
}

impl CompilationBuilder {
    /// Takes the ZPL source file. By default the configuration file is assumed
    /// to have the same base name but with a `.zplc` extension instead of `.zpl`.
    pub fn new(source: PathBuf) -> Self {
        Self {
            source_zpl: source,
            ..Default::default()
        }
    }

    /// Enable verbose console output from the compilation process.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// If set true, treat warnings as errors and halt compilation when they occur.
    pub fn werror(mut self, werror: bool) -> Self {
        self.werror = werror;
        self
    }

    /// Just builds the fabric in memory, does not try to create the policy protobuf binary.
    pub fn parse_only(mut self, parse_only: bool) -> Self {
        self.parse_only = parse_only;
        self
    }

    /// Emit structured advisory diagnostics without changing compilation decisions.
    pub fn lint(mut self, lint: bool) -> Self {
        self.lint = lint;
        self
    }

    /// Set the path to the configuration to use with the compilation.
    /// This is optional. If not set, the configuration file is assumed to have
    /// the same base name as the source file but with a `.zplc` extension.
    pub fn config(mut self, config: &Path) -> Self {
        self.source_config = Some(config.into());
        self
    }

    pub fn sign_with_key(mut self, key: Rsa<Private>) -> Self {
        self.private_key = Some(key);
        self
    }

    pub fn output_directory(mut self, output_directory: &Path) -> Self {
        self.output_directory = Some(output_directory.into());
        self
    }

    pub fn output_filename(mut self, out_filename: &str) -> Self {
        self.out_filename = Some(out_filename.into());
        self
    }

    pub fn output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }

    /// Create the [Compilation] object with the settings configured.
    pub fn build(self) -> Compilation {
        // Default config is same name as source replace .zpl extension with .zplc extension
        let config = match self.source_config {
            Some(config) => config,
            None => {
                let mut config = self.source_zpl.clone();
                config.set_extension("zplc");
                config
            }
        };

        let default_extension = match self.output_format {
            OutputFormat::V2 => "bin2",
            _ => panic!("unsupported output format"),
        };

        let mut output_file = match self.output_directory {
            Some(outdir) => {
                if !outdir.is_dir() {
                    panic!(
                        "output directory {:?} does not exist or is not a directory",
                        outdir
                    );
                }
                let ofile = self.source_zpl.with_extension(default_extension);
                outdir.join(ofile.file_name().unwrap())
            }
            None => self.source_zpl.with_extension(default_extension),
        };

        // If user has selected an alternate output file, substitute that in now.
        if let Some(out_filename) = self.out_filename {
            let base = output_file.parent().unwrap();
            output_file = base.join(out_filename);
        }

        Compilation {
            verbose: self.verbose,
            werror: self.werror,
            lint: self.lint,
            source_zpl: self.source_zpl,
            source_config: config,
            output_file,
            private_key: self.private_key,
            parse_only: self.parse_only,
            output_format: self.output_format,
            copied_allow_statements: None,
            copied_never_allow_statements: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use bytes::{Buf, Bytes};
    use std::env;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zpr::policy::v1 as policy_capnp;

    struct TempDir {
        path: PathBuf,
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path)
                .expect("failed to remove compilation test temp dir");
        }
    }

    impl TempDir {
        fn new(name_hint: &str) -> Self {
            let mut temp_dir = env::temp_dir();
            temp_dir.push(format!(
                "compilation-test-{}-{}-{}",
                name_hint,
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ));
            std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir for zpc output");
            TempDir { path: temp_dir }
        }
    }

    const BASIC_CONFIG: &str = r#"
    [nodes.n0]
    zpr_address = "fd5a:5052:90de::1"
    interfaces = [ "in1" ]
    in1.netaddr = "127.0.0.1:5000"
    provider = [["device.zpr.adapter.cn", "fee"]]

    [visa_service]
    dock_node = "n0"

    [trusted_services.default]
    cert_path = ""

    [protocols.http]
    l4protocol = "iana.TCP"
    port = 80

    [services.Webby]
    protocol = "http"
    "#;

    // Includes a trusted service
    const BAS_CONFIG: &str = r#"
    [nodes.n0]
    key = "none"
    zpr_address = "fd5a:5052:90de::1"
    interfaces = [ "in1" ]
    in1.netaddr = "127.0.0.1:5000"
    provider = [["device.zpr.adapter.cn", "fee"]]

    [visa_service]
    dock_node = "n0"

    [trusted_services.default]
    cert_path = ""

    [trusted_services.bas]
    api = "validation/2"
    client = "AuthService"
    cert_path = ""
    returns_attributes = [ "color -> user.color", "content -> service.content", "bas_id -> user.bas_id" ]
    identity_attributes = [ "bas_id" ]
    provider = [[ "device.zpr.adapter.cn", "bas.zpr.org" ]]


    [protocols.http]
    l4protocol = "iana.TCP"
    port = 80

    [services.Webby]
    protocol = "http"

    [services.bas-vs]
    protocol = "zpr-validation2"

    [services.AuthService]
    protocol = "zpr-oauthrsa"
    "#;

    #[test]
    fn simple_compile() {
        let zpl = r#"
        define Webby as service with device.zpr.adapter.cn.
        provide Webby at webby.svc.zpr over TCP 80.
        allow zpr.adapter.cn: devices.
        "#;

        let tempdir = TempDir::new("simple_compile");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(
            result.is_ok(),
            "compilation failed: {}",
            result.unwrap_err()
        );
    }

    // In this case with is required since there is no provider in config.
    #[test]
    fn define_requires_with() {
        let zpl = r#"
        define Webby as service.
        provide Webby at webby.svc.zpr over TCP 80.
        allow zpr.adapter.cn: devices.
        "#;

        let tempdir = TempDir::new("define_requires_with");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("service with no attributes"),
            "unexpected error message: {}",
            err_msg
        );
    }

    // An embedded service declaration scopes the following policy while its contract
    // and provider attributes continue to come from configuration.
    #[test]
    fn embedded_service_uses_configured_contract() {
        let zplc = r#"
        [nodes.n0]
        key = "none"
        zpr_address = "fd5a:5052:90de::1"
        interfaces = [ "in1" ]
        in1.netaddr = "127.0.0.1:5000"
        provider = [["device.zpr.adapter.cn", "fee"]]

        [visa_service]
        dock_node = "n0"

        [trusted_services.default]
        cert_path = ""

        [protocols.http]
        l4protocol = "iana.TCP"
        port = 80

        [services.Webby]
        protocol = "http"
        provider = [["device.zpr.adapter.cn", ""]]
        "#;

        let zpl = r#"
        define Webby as service with device.zpr.adapter.cn.
        service Webby as json {"service_class":"Webby"}.
        allow zpr.adapter.cn: devices.
        "#;

        let tempdir = TempDir::new("embedded_service_uses_configured_contract");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, zplc).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(
            result.is_ok(),
            "compilation failed: {}",
            result.unwrap_err()
        );
    }

    #[test]
    fn cannot_use_cn_as_tag() {
        let zpl = r#"
        define Webby as service with device.zpr.adapter.cn.
        provide Webby at webby.svc.zpr over TCP 80.
        allow zpr.adapter.cn devices.
        "#;

        let tempdir = TempDir::new("cannot_use_cn_as_tag");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cn attribute used as a tag"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[test]
    fn test_svc_attrs_must_be_defined() {
        let zpl = r#"
        define Webby as service with unknown_attr.
        provide Webby at webby.svc.zpr over TCP 80.
        allow cn: devices.
        "#;

        let tempdir = TempDir::new("test_svc_attrs_must_be_defined");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown_attr not found"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[test]
    fn test_allow_attrs_must_be_defined() {
        let zpl = r#"
        define Webby as service with device.zpr.adapter.cn.
        provide Webby at webby.svc.zpr over TCP 80.
        allow unknown_attr: devices.
        "#;

        let tempdir = TempDir::new("test_allow_attrs_must_be_defined");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let result = compilation.compile();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("device.unknown_attr: not found"),
            "unexpected error message: {}",
            err_msg
        );
    }

    #[test]
    fn test_service_attributes() {
        let zpl = r#"
        define GreenWebby as a service with content:green.
        define BrownWebby as a service with content:brown.
        define Webby as a service with device.zpr.adapter.cn.
        provide GreenWebby at green.svc.zpr over TCP 80.
        allow color:green users.
        provide BrownWebby at brown.svc.zpr over TCP 80.
        allow color:brown users.
        provide Webby at webby.svc.zpr over TCP 80.
        allow color:red users.
        "#;

        let tempdir = TempDir::new("test_service_attributes");
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");

        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BAS_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file)
            .config(&cfg_file)
            .verbose(true)
            .build();

        let ctx = CompilationCtx::new(true, false);
        let result = compilation.compile_to_policy(&ctx);
        match result {
            Ok(pol) => {
                let pol_bin = pol.unwrap();

                let policy_bytes = Bytes::from(pol_bin);
                let policy_rdr = capnp::serialize::read_message(
                    policy_bytes.reader(),
                    capnp::message::ReaderOptions::new(),
                )
                .unwrap();

                let pol = policy_rdr
                    .get_root::<policy_capnp::policy::Reader>()
                    .unwrap();

                let mut pcount = 0;

                let mut matched: u8 = 0;

                assert!(pol.has_com_policies()); // we are checking communication policies.

                for plcy in pol.get_com_policies().unwrap().iter() {
                    let svc_id = plcy.get_service_id().unwrap().to_string().unwrap();
                    let expected_color = match svc_id.as_str() {
                        "green.svc.zpr" => "green",
                        "brown.svc.zpr" => "brown",
                        "webby.svc.zpr" => "red",
                        _ => continue,
                    };
                    pcount += 1;
                    let conds: Vec<String> = plcy
                        .get_client_conds()
                        .unwrap()
                        .iter()
                        .map(|condition| attr_exp_v2_to_string(&condition))
                        .collect();
                    assert!(conds.contains(&format!("user.color EQ {expected_color}")));
                    assert!(conds.contains(&"user.zpr.authority HAS \"\"".to_string()));
                    assert!(plcy.get_service_conds().unwrap().is_empty());
                    matched |= match expected_color {
                        "red" => 0b00000001,
                        "brown" => 0b00000010,
                        _ => 0b00000100,
                    };
                }
                assert!(
                    pcount == 3,
                    "expected 3 provided service policies, got {}",
                    pcount
                );
                assert!(
                    matched == 0b00000111,
                    "did not match all expected policies, got {:03b}",
                    matched
                );
            }
            Err(err) => {
                assert!(false, "compilation failed: {}", err);
            }
        }
    }

    fn attr_exp_v2_to_string(exp: &policy_capnp::attr_expr::Reader) -> String {
        let mut s = String::new();
        s.push_str(&exp.get_key().unwrap().to_str().unwrap());
        let opstr = match exp.get_op().unwrap() {
            policy_capnp::AttrOp::Eq => "EQ",
            policy_capnp::AttrOp::Ne => "NE",
            policy_capnp::AttrOp::Has => "HAS",
            policy_capnp::AttrOp::Excludes => "EXCLUDES",
        };
        s.push_str(&format!(" {} ", opstr));
        if exp.has_value() {
            let vals = exp.get_value().unwrap();
            if vals.len() > 1 {
                s.push_str("[");
                s.push_str(
                    &vals
                        .iter()
                        .map(|v| v.unwrap().to_str().unwrap())
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                s.push_str("]");
            } else if vals.len() == 1 {
                s.push_str(&vals.get(0).unwrap().to_str().unwrap());
            } else {
                s.push_str("\"\"");
            }
        } else {
            s.push_str("(no value)")
        }
        s
    }

    // ---- Authority presence markers, end to end (issue #144) ----

    /// Compile the given ZPL against BASIC_CONFIG and return, per com-policy,
    /// (service_id, allow, sorted client condition strings, sorted service
    /// condition strings).
    fn compile_to_com_policies(
        name_hint: &str,
        zpl: &str,
    ) -> Vec<(String, bool, Vec<String>, Vec<String>)> {
        let tempdir = TempDir::new(name_hint);
        let zpl_file = tempdir.path.join("test.zpl");
        std::fs::write(&zpl_file, zpl).expect("failed to write zpl file");
        let cfg_file = tempdir.path.join("test.zplc");
        std::fs::write(&cfg_file, BASIC_CONFIG).expect("failed to write config file");

        let mut compilation = Compilation::builder(zpl_file).config(&cfg_file).build();
        let ctx = CompilationCtx::default();
        let pol_bin = compilation
            .compile_to_policy(&ctx)
            .expect("compilation failed")
            .unwrap();

        let policy_bytes = Bytes::from(pol_bin);
        let policy_rdr = capnp::serialize::read_message(
            policy_bytes.reader(),
            capnp::message::ReaderOptions::new(),
        )
        .unwrap();
        let pol = policy_rdr
            .get_root::<policy_capnp::policy::Reader>()
            .unwrap();

        let mut out = Vec::new();
        for plcy in pol.get_com_policies().unwrap().iter() {
            let svc_id = plcy.get_service_id().unwrap().to_string().unwrap();
            let mut conds: Vec<String> = plcy
                .get_client_conds()
                .unwrap()
                .iter()
                .map(|c| attr_exp_v2_to_string(&c))
                .collect();
            conds.sort();
            let mut svc_conds: Vec<String> = plcy
                .get_service_conds()
                .unwrap()
                .iter()
                .map(|c| attr_exp_v2_to_string(&c))
                .collect();
            svc_conds.sort();
            out.push((svc_id, plcy.get_allow(), conds, svc_conds));
        }
        out
    }

    // A bare `allow users ...` must no longer compile to an empty client
    // condition: it carries `has user.zpr.authority` (issue #144).
    #[test]
    fn test_authority_marker_end_to_end_bare_users() {
        let policies = compile_to_com_policies(
            "auth-marker-users",
            "define Webby as service with device.zpr.adapter.cn.\nprovide Webby at webby.svc.zpr over TCP 80.\nallow users.\n",
        );
        let webby: Vec<_> = policies.iter().filter(|p| p.0 == "webby.svc.zpr").collect();
        assert_eq!(webby.len(), 1, "expected one Webby policy: {policies:?}");
        assert_eq!(webby[0].2, vec!["user.zpr.authority HAS \"\""]);
    }

    // An authored value on the marker key squashes with the injected valueless
    // marker into a single Eq condition -- no duplicate Has.
    #[test]
    fn test_authority_marker_authored_value_squashes_to_eq() {
        let policies = compile_to_com_policies(
            "auth-marker-valued",
            "define Webby as service with device.zpr.adapter.cn.\nprovide Webby at webby.svc.zpr over TCP 80.\nallow user.zpr.authority:google users.\n",
        );
        let webby: Vec<_> = policies.iter().filter(|p| p.0 == "webby.svc.zpr").collect();
        assert_eq!(webby.len(), 1, "expected one Webby policy: {policies:?}");
        assert_eq!(webby[0].2, vec!["user.zpr.authority EQ google"]);
    }

    // `never allow users ...` is untouched: the deny still compiles to an
    // empty client condition (denies every actor, fail-closed).
    #[test]
    fn test_authority_marker_not_injected_in_never() {
        let policies = compile_to_com_policies(
            "auth-marker-never",
            "define Webby as service with device.zpr.adapter.cn.\nprovide Webby at webby.svc.zpr over TCP 80.\nallow devices.\nnever allow users.\n",
        );
        let deny: Vec<_> = policies
            .iter()
            .filter(|p| p.0 == "webby.svc.zpr" && !p.1)
            .collect();
        assert_eq!(deny.len(), 1, "expected one deny policy: {policies:?}");
        assert!(
            deny[0].2.is_empty(),
            "never-allow client condition must stay empty: {:?}",
            deny[0].2
        );
    }

    // The VisaService admin path picks up the markers from the same clause
    // data as the regular path, and a bare service-scoped `allow users.`
    // now emits a real admin condition (previously it emitted nothing and the
    // compiler warned "no policy granting admin access to VisaService").
    #[test]
    fn test_authority_marker_on_visa_admin_path() {
        let policies = compile_to_com_policies(
            "auth-marker-admin",
            "define Webby as service with device.zpr.adapter.cn.\nprovide VisaService at visa-admin.svc.zpr over TCP 443.\nallow users.\nprovide Webby at webby.svc.zpr over TCP 80.\nallow devices.\n",
        );
        let admin: Vec<_> = policies
            .iter()
            .filter(|p| p.0 == "/zpr/visaservice/admin")
            .collect();
        assert_eq!(
            admin.len(),
            1,
            "expected one VisaService admin policy: {policies:?}"
        );
        assert_eq!(admin[0].2, vec!["user.zpr.authority HAS \"\""]);
    }

    // A device clause on the client side must retain its authority marker.
    #[test]
    fn test_authority_marker_end_to_end_device_subject() {
        let policies = compile_to_com_policies(
            "auth-marker-device-subject",
            "define Webby as service with device.zpr.adapter.cn.\nprovide Webby at webby.svc.zpr over TCP 80.\nallow users on devices.\n",
        );
        let webby: Vec<_> = policies.iter().filter(|p| p.0 == "webby.svc.zpr").collect();
        assert_eq!(webby.len(), 1, "expected one Webby policy: {policies:?}");
        assert!(
            webby[0]
                .2
                .contains(&"user.zpr.authority HAS \"\"".to_string())
        );
        assert!(
            webby[0]
                .2
                .contains(&"device.zpr.authority HAS \"\"".to_string())
        );
    }
}
