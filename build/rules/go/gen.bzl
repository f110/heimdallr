load("@bazel_skylib//lib:shell.bzl", "shell")
load("@bazel_skylib//lib:paths.bzl", "paths")
load("@bazel_skylib//lib:collections.bzl", "collections")
load("@io_bazel_rules_go//go:def.bzl", "go_context", "go_rule")
load("@io_bazel_rules_go//go/private:providers.bzl", "GoLibrary", "GoSource")

_DEFAULT_CLIENTSET_NAME = "versioned"
_COMMON_ATTRS = {
    "dir": attr.string(),
    "srcs": attr.label_list(),
    "header": attr.label(
        allow_single_file = True,
    ),
    "no_gazelle": attr.bool(default = False),
    "debug": attr.bool(default = False),
    "_template": attr.label(
        default = "//build/rules/go:code-generator.bash",
        allow_single_file = True,
    ),
    "_gazelle": attr.label(
        default = "@bazel_gazelle//cmd/gazelle",
        executable = True,
        cfg = "host",
    ),
}

def _code_generator_impl(ctx, _bin, srcs, args, target_dirs = [], generated_dirs = [], filename = "", dep_runfiles = [], providers = []):
    go = go_context(ctx)

    package_dirs = []
    src_dirs = []
    for v in providers:
        package_dirs.append(v[GoLibrary].importpath)
        src_dirs.append(v[GoSource].srcs[0].dirname)

    debug = "false"
    if ctx.attr.debug:
        args.append("-v=5")
        debug = "true"

    no_gazelle = "false"
    if ctx.attr.no_gazelle:
        no_gazelle = "true"

    substitutions = {
        "@@GAZELLE@@": shell.quote(ctx.executable._gazelle.short_path),
        "@@BIN@@": shell.quote(_bin.short_path),
        "@@ARGS@@": shell.array_literal(args),
        "@@TARGET_DIRS@@": shell.array_literal(target_dirs),
        "@@GENERATED_DIRS@@": shell.array_literal(generated_dirs),
        "@@FILENAME@@": shell.quote(filename),
        "@@SRC_PACKAGE_DIRS@@": shell.array_literal(package_dirs),
        "@@SRC_DIRS@@": shell.array_literal(src_dirs),
        "@@GO_ROOT@@": shell.quote(paths.dirname(go.sdk.root_file.path)),
        "@@NO_GAZELLE@@": shell.quote(no_gazelle),
        "@@DEBUG@@": debug,
    }
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = out,
        substitutions = substitutions,
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = [_bin, ctx.executable._gazelle, ctx.file.header] + srcs, transitive_files = depset(dep_runfiles + go.sdk.srcs))
    return [
        DefaultInfo(
            runfiles = runfiles,
            executable = out,
        ),
    ]

def _extract_src_and_providers(go_srcs):
    srcs = []
    input_path = {}
    for x in go_srcs:
        for v in x[GoSource].srcs:
            srcs.append(v)

            if not v.dirname in input_path:
                input_path[v.dirname] = x

    return srcs, [input_path[k] for k in input_path.keys()]

def _input_dir_args(providers):
    imports = {}
    for v in providers:
        imports[v[GoLibrary].importpath] = True

    return [x for x in imports.keys()]

def _find_module_name(packagename, dir):
    p = reversed(packagename.split("/"))
    d = reversed(dir.split("/"))

    return paths.join(*reversed(p[len(d):]))

def _flatten_deps(go_srcs):
    go_srcs = [x[GoSource] for x in go_srcs]
    prev_len = 0
    result = {}
    srcs = []
    for x in go_srcs:
        srcs += x.deps

    for i in range(10):
        next_srcs = []
        for x in srcs:
            if not x[GoSource].library.importpath in result:
                result[x[GoSource].library.importpath] = x[GoSource]
                next_srcs += x[GoSource].deps

        if not next_srcs:
            break
        else:
            srcs = next_srcs

    deps = []
    for k in result.keys():
        deps += result[k].srcs

    return deps

def _deepcopy_gen_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".sh")

    go_srcs = ctx.attr.srcs
    srcs, providers = _extract_src_and_providers(go_srcs)
    dep_runfiles = _flatten_deps(go_srcs)

    args = []
    args.append("--input-dirs=%s" % ",".join(_input_dir_args(providers)))
    args.append("--bounding-dirs=%s" % ",".join(_input_dir_args(providers)))
    args.append("--go-header-file=%s" % ctx.file.header.path)
    args.append("--output-file-base=%s" % ctx.attr.outputname)

    return _code_generator_impl(
        ctx,
        ctx.executable._deepcopy_gen,
        srcs,
        args,
        filename = ctx.attr.outputname + ".go",
        target_dirs = [v[GoSource].srcs[0].dirname for v in providers],
        generated_dirs = [v[GoLibrary].importpath for v in providers],
        dep_runfiles = dep_runfiles,
        providers = providers,
    )

_deepcopy_gen = go_rule(
    implementation = _deepcopy_gen_impl,
    executable = True,
    attrs = dict({
        "outputname": attr.string(
            default = "zz_generated.deepcopy",
        ),
        "_deepcopy_gen": attr.label(
            default = "//third_party/code-generator/cmd/deepcopy-gen",
            executable = True,
            cfg = "host",
        ),
    }.items() + _COMMON_ATTRS.items()),
)

def _client_gen_impl(ctx):
    go = go_context(ctx)

    go_srcs = ctx.attr.srcs
    srcs, providers = _extract_src_and_providers(go_srcs)
    dep_runfiles = _flatten_deps(go_srcs)

    module_name = ""
    for v in providers:
        if v[GoSource].srcs[0].dirname.startswith("vendor/"):
            continue
        x = _find_module_name(v[GoLibrary].importpath, v[GoSource].srcs[0].dirname)
        if module_name != "" and module_name != x:
            fail("Could not detect module name")
        else:
            module_name = x
    target_dir = ctx.attr.clientpackage[len(module_name) + 1:]

    args = []
    args.append("--input=%s" % ",".join(_input_dir_args(providers)))
    args.append("--input-base")
    args.append("")
    args.append("--go-header-file=%s" % ctx.file.header.path)
    args.append("--clientset-name=%s" % ctx.attr.clientsetname)
    args.append("--output-package=%s" % ctx.attr.clientpackage)

    return _code_generator_impl(
        ctx,
        ctx.executable._client_gen,
        srcs,
        args,
        target_dirs = [target_dir],
        generated_dirs = [ctx.attr.clientpackage],
        dep_runfiles = dep_runfiles,
        providers = providers,
    )

_client_gen = go_rule(
    implementation = _client_gen_impl,
    executable = True,
    attrs = dict({
        "clientsetname": attr.string(
            default = _DEFAULT_CLIENTSET_NAME,
        ),
        "clientpackage": attr.string(),
        "_client_gen": attr.label(
            default = "//third_party/code-generator/cmd/client-gen",
            executable = True,
            cfg = "host",
        ),
    }.items() + _COMMON_ATTRS.items()),
)

def _lister_gen_impl(ctx):
    go = go_context(ctx)

    go_srcs = ctx.attr.srcs
    srcs, providers = _extract_src_and_providers(go_srcs)
    dep_runfiles = _flatten_deps(go_srcs)

    module_name = ""
    for v in providers:
        if v[GoSource].srcs[0].dirname.startswith("vendor/"):
            continue
        x = _find_module_name(v[GoLibrary].importpath, v[GoSource].srcs[0].dirname)
        if module_name != "" and module_name != x:
            fail("Could not detect module name")
        else:
            module_name = x
    target_dir = ctx.attr.listerpackage[len(module_name) + 1:]

    args = []
    args.append("--input-dirs=%s" % ",".join(_input_dir_args(providers)))
    args.append("--go-header-file=%s" % ctx.file.header.path)
    args.append("--output-package=%s" % ctx.attr.listerpackage)

    return _code_generator_impl(
        ctx,
        ctx.executable._lister_gen,
        srcs,
        args,
        target_dirs = [target_dir],
        generated_dirs = [ctx.attr.listerpackage],
        dep_runfiles = dep_runfiles,
        providers = providers,
    )

_lister_gen = go_rule(
    implementation = _lister_gen_impl,
    executable = True,
    attrs = dict({
        "listerpackage": attr.string(),
        "_lister_gen": attr.label(
            default = "//third_party/code-generator/cmd/lister-gen",
            executable = True,
            cfg = "host",
        ),
    }.items() + _COMMON_ATTRS.items()),
)

def _informer_gen_impl(ctx):
    go = go_context(ctx)

    go_srcs = ctx.attr.srcs
    srcs, providers = _extract_src_and_providers(go_srcs)
    dep_runfiles = _flatten_deps(go_srcs)

    module_name = ""
    for v in providers:
        if v[GoSource].srcs[0].dirname.startswith("vendor/"):
            continue
        x = _find_module_name(v[GoLibrary].importpath, v[GoSource].srcs[0].dirname)
        if module_name != "" and module_name != x:
            fail("Could not detect module name")
        else:
            module_name = x
    target_dir = ctx.attr.informerpackage[len(module_name) + 1:]

    args = []
    args.append("--input-dirs=%s" % ",".join(_input_dir_args(providers)))
    args.append("--go-header-file=%s" % ctx.file.header.path)
    args.append("--versioned-clientset-package=%s/%s" % (ctx.attr.clientpackage, ctx.attr.clientsetname))
    args.append("--listers-package=%s" % ctx.attr.listerpackage)
    args.append("--output-package=%s" % ctx.attr.informerpackage)

    return _code_generator_impl(
        ctx,
        ctx.executable._informer_gen,
        srcs,
        args,
        target_dirs = [target_dir],
        generated_dirs = [ctx.attr.informerpackage],
        dep_runfiles = dep_runfiles,
        providers = providers,
    )

_informer_gen = go_rule(
    implementation = _informer_gen_impl,
    executable = True,
    attrs = dict({
        "informerpackage": attr.string(),
        "clientpackage": attr.string(),
        "clientsetname": attr.string(default = _DEFAULT_CLIENTSET_NAME),
        "listerpackage": attr.string(),
        "_informer_gen": attr.label(
            default = "//third_party/code-generator/cmd/informer-gen",
            executable = True,
            cfg = "host",
        ),
    }.items() + _COMMON_ATTRS.items()),
)

def _crd_gen_impl(ctx):
    go_srcs = ctx.attr.srcs

    srcs = []
    import_paths = []
    src_dirs = {}
    for v in go_srcs:
        if v[GoLibrary].label.package.startswith("vendor/"):
            continue
        srcs += v[GoSource].srcs
        import_paths.append(v[GoLibrary].importmap)
        src_dirs[v[GoSource].srcs[0].dirname.split("/")[0]] = True

    dep_files = _flatten_deps(go_srcs)

    module_name = ""
    for v in go_srcs:
        if v[GoSource].srcs[0].dirname.startswith("vendor/"):
            continue
        x = _find_module_name(v[GoLibrary].importpath, v[GoSource].srcs[0].dirname)
        if module_name != "" and module_name != x:
            fail("Could not detect module name")
        else:
            module_name = x

    args = [
        "crd:trivialVersions=true",
        "crd:crdVersions=v1",
    ]
    for v in import_paths:
        args.append("paths=%s" % v)
    args.append("output:crd:artifacts:config=crd")

    debug = "false"
    if ctx.attr.debug:
        debug = "true"

    substitutions = {
        "@@DEBUG@@": shell.quote(debug),
        "@@BIN@@": shell.quote(ctx.executable._bin.short_path),
        "@@GENERATED_DIR@@": shell.quote("crd"),
        "@@OUTPUT_DIR@@": shell.quote(ctx.attr.dir),
        "@@ARGS@@": shell.array_literal(args),
        "@@SRC_PACKAGE_NAMES@@": shell.array_literal(import_paths),
        "@@SRC_DIRS@@": shell.array_literal([x for x in src_dirs.keys()]),
        "@@MODULE@@": shell.quote(module_name),
    }
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = out,
        substitutions = substitutions,
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = [ctx.executable._bin] + srcs, transitive_files = depset(dep_files))
    return [
        DefaultInfo(
            runfiles = runfiles,
            executable = out,
        ),
    ]

_crd_gen = rule(
    implementation = _crd_gen_impl,
    executable = True,
    attrs = {
        "dir": attr.string(),
        "srcs": attr.label_list(),
        "debug": attr.bool(default = False),
        "_template": attr.label(
            default = "//build/rules/go:controller-gen.bash",
            allow_single_file = True,
        ),
        "_bin": attr.label(
            default = "//third_party/controller-tools/cmd/controller-gen",
            executable = True,
            cfg = "host",
        ),
    },
)

def k8s_code_generator(name, **kwargs):
    if not "dir" in kwargs:
        kwargs["dir"] = native.package_name()

    deepcopy_args = {}
    client_args = {}
    lister_args = {}
    informer_args = {}
    for k in _COMMON_ATTRS.keys():
        if k in kwargs:
            deepcopy_args[k] = kwargs[k]
            client_args[k] = kwargs[k]
            lister_args[k] = kwargs[k]
            informer_args[k] = kwargs[k]

    for k in ["outputname"]:
        if k in kwargs:
            deepcopy_args[k] = kwargs[k]

    for k in ["clientpackage", "clientsetname"]:
        if k in kwargs:
            client_args[k] = kwargs[k]

    for k in ["listerpackage"]:
        if k in kwargs:
            lister_args[k] = kwargs[k]

    for k in ["informerpackage", "clientpackage", "listerpackage", "clientsetname"]:
        if k in kwargs:
            informer_args[k] = kwargs[k]

    crd_args = {
        "dir": kwargs["crd"],
        "srcs": kwargs["srcs"],
    }

    _deepcopy_gen(name = name + ".deepcopy", **deepcopy_args)
    _client_gen(name = name + ".client", **client_args)
    _lister_gen(name = name + ".lister", **lister_args)
    _informer_gen(name = name + ".informer", **informer_args)
    _crd_gen(name = name + ".crd", **crd_args)

def _rbac_gen_impl(ctx):
    go_srcs = ctx.attr.srcs

    srcs = []
    import_paths = []
    src_dirs = {}
    for v in go_srcs:
        if v[GoLibrary].label.package.startswith("vendor/"):
            continue
        srcs += v[GoSource].srcs
        import_paths.append(v[GoLibrary].importmap)
        src_dirs[v[GoSource].srcs[0].dirname.split("/")[0]] = True

    dep_files = _flatten_deps(go_srcs)
    for x in dep_files:
        if x.path.startswith("vendor/"):
            continue
        src_dirs[paths.dirname(x.path).split("/")[0]] = True

    module_name = ""
    for v in go_srcs:
        if v[GoSource].srcs[0].dirname.startswith("vendor/"):
            continue
        x = _find_module_name(v[GoLibrary].importpath, v[GoSource].srcs[0].dirname)
        if module_name != "" and module_name != x:
            fail("Could not detect module name")
        else:
            module_name = x

    args = [
        ("rbac:roleName=%s" % ctx.attr.rolename),
    ]
    for v in import_paths:
        args.append("paths=%s" % v)
    args.append("output:rbac:dir=rbac")

    debug = "false"
    if ctx.attr.debug:
        debug = "true"

    substitutions = {
        "@@DEBUG@@": shell.quote(debug),
        "@@BIN@@": shell.quote(ctx.executable._bin.short_path),
        "@@GENERATED_DIR@@": shell.quote("rbac"),
        "@@OUTPUT_DIR@@": shell.quote(ctx.attr.dir),
        "@@ARGS@@": shell.array_literal(args),
        "@@SRC_PACKAGE_NAMES@@": shell.array_literal(import_paths),
        "@@SRC_DIRS@@": shell.array_literal([x for x in src_dirs.keys()]),
        "@@MODULE@@": shell.quote(module_name),
    }
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = out,
        substitutions = substitutions,
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = [ctx.executable._bin] + srcs, transitive_files = depset(dep_files))
    return [
        DefaultInfo(
            runfiles = runfiles,
            executable = out,
        ),
    ]

rbac_gen = rule(
    implementation = _rbac_gen_impl,
    executable = True,
    attrs = {
        "dir": attr.string(),
        "srcs": attr.label_list(),
        "rolename": attr.string(),
        "debug": attr.bool(default = False),
        "_template": attr.label(
            default = "//build/rules/go:controller-gen.bash",
            allow_single_file = True,
        ),
        "_bin": attr.label(
            default = "//third_party/controller-tools/cmd/controller-gen",
            executable = True,
            cfg = "host",
        ),
    },
)