import json

def ptr_to_ref_type(ty: str) -> str:
    ty_decomp = ty.split(" ")
    if ty_decomp[0] == "*const":
        ty_decomp[0] = "&"
    elif ty_decomp[0] == "*mut":
        ty_decomp[0] = "&mut"
    return " ".join(ty_decomp)

def strip_ptr_type(ty: str) -> str:
    ty_decomp = ty.split(" ")
    if ty_decomp[0] in {"*const", "*mut"}:
        del ty_decomp[0]
    else:
        raise ValueError(f"expected a pointer type, found `{ty}`")
    return " ".join(ty_decomp)

def ptr_wrap_maybeuninit_type(ty: str) -> str:
    ty_decomp = ty.split(" ")
    if ty_decomp[0] in {"*const", "*mut"}:
        if not ty_decomp[1].startswith("MaybeUninit<"):
            ty_decomp.insert(1, "MaybeUninit<")
            ty_decomp.append(">")
    else:
        raise ValueError("expected a pointer type")
    return " ".join(ty_decomp)

class Rust:
    def __init__(self):
        self.binding = ""
        self.wrapping = ""
        self.header = ""

class Impl:
    def __init__(self, level: int, impl: str):
        self.level = level
        self.impl = impl
        self.IMPL = impl.upper()
        self.namespace_prefix = f"PQCLEAN_DILITHIUM{self.level}_{self.IMPL}_"

def process_function_wrapping(rust: Rust, function: dict, wrapping_conf: dict, impl: Impl, add_binding: bool = True):
    name = function["name"]
    c_name = impl.namespace_prefix + name
    has_return = function.get("return", None) is not None
    uninit_mutate_init_return = wrapping_conf.get("uninit_mutate_init_return", [])
    return_result = wrapping_conf.get("return_as_result", None) is not None
    if return_result:
        assert has_return
    wrapping_return = has_return or (len(uninit_mutate_init_return) != 0)
    wrapping_name = name + wrapping_conf.get("name_postfix", "")
    arg_mapping_from = wrapping_conf.get("arg_mapping_from", {})

    ### Compute some facts for each argument
    augmented_args = []
    args_lookup = dict()
    for i, arg in enumerate(function["args"]):
        arg_name = arg[0]
        arg_base_type = arg[1]
        arg_is_mapped = arg_name in arg_mapping_from
        arg_in_wrapping = (arg_name not in uninit_mutate_init_return) and not arg_is_mapped
        assert not ((arg_name in uninit_mutate_init_return) and arg_is_mapped)
        arg_binding_type = arg_base_type
        if arg_in_wrapping:
            arg_wrapping_type = ptr_to_ref_type(arg_base_type)
        else:
            arg_wrapping_type = None
        if arg_name in uninit_mutate_init_return:
            arg_return_type = strip_ptr_type(arg_base_type)
        else:
            arg_return_type = None
        if arg_is_mapped:
            mapped_arg = args_lookup[arg_mapping_from[arg_name]]
            if wrapping_conf.get("map_types", "implicit") == "implicit":
                assert strip_ptr_type(arg_base_type) == strip_ptr_type(mapped_arg["base_type"])
            if mapped_arg["return_type"] is not None:
                if arg_base_type.startswith("*const "):
                    arg_binding_type = "*const " + strip_ptr_type(mapped_arg["base_type"])
                elif arg_base_type.startswith("*mut "):
                    arg_binding_type = "*mut " + strip_ptr_type(mapped_arg["base_type"])
                else:
                    raise ValueError(f"expected pointer type for mapped arg {arg_name}")
        else:
            mapped_arg = None

        arg_info = {
            "id" : arg_name,
            "name" : arg_name,
            "base_type" : arg_base_type,
            "in_wrapping" : arg_in_wrapping,
            "binding_type" : arg_binding_type,
            "binding_position" : i,
            "wrapping_type" : arg_wrapping_type,
            "return_type" : arg_return_type,
            "is_mapped": arg_is_mapped,
            "mapped_arg": mapped_arg,
        }
        augmented_args.append(arg_info)
        args_lookup[arg_name] = arg_info

    ### Add to the link section `rust.binding`
    if add_binding:
        rust.binding += f"    fn {c_name}("
        rust.binding += ", ".join([f"{arg['name']}: {arg['binding_type']}" for arg in augmented_args])
        rust.binding += ")"
        if has_return:
            rust.binding += f" -> {function['return']}"
        rust.binding += ";\n"

    ### Add to the wrapping functions section `rust.wrapping`
    # Add documentation
    descr = wrapping_conf.get("description", None)
    if descr is not None:
        rust.wrapping += "/// " + descr + "\n"
    ## Add function declaration
    rust.wrapping += f"pub fn {wrapping_name}("
    rust.wrapping += ", ".join([f"{arg['name']}: {arg['wrapping_type']}" for arg in augmented_args if arg["in_wrapping"]])
    rust.wrapping += f")"
    # Construct the return type
    if wrapping_return:
        rust.wrapping += f" -> "
        if has_return and not return_result:
            assert len(uninit_mutate_init_return) == 0
            rust.wrapping += f"{function['return']}"
        else:
            if return_result:
                rust.wrapping += f"Result<"
            if len(uninit_mutate_init_return) != 1:
                rust.wrapping += f"("
            rust.wrapping += ", ".join([args_lookup[arg_id]["return_type"] for arg_id in uninit_mutate_init_return])
            if len(uninit_mutate_init_return) != 1:
                rust.wrapping += f")"
            if return_result:
                rust.wrapping += f", ()>"

    ## Add function implementation
    rust.wrapping += f" {{\n"
    # Create uninitialized variables as necessary for return types
    for arg_id in uninit_mutate_init_return:
        arg = args_lookup[arg_id]
        rust.wrapping += f"    let mut {arg['name']} = MaybeUninit::<{arg['return_type']}>::uninit();\n"

    # Call the C function through FFI
    rust.wrapping += f"    "
    if has_return:
        rust.wrapping += f"let res = "
    rust.wrapping += f"unsafe {{ {c_name}(\n"
    for arg in augmented_args:
        rust.wrapping += "        "
        if arg["is_mapped"]:
            refer_arg = arg['mapped_arg']
        else:
            refer_arg = arg

        rust.wrapping += f"{refer_arg['name']}"

        if refer_arg["return_type"] is not None:
            rust.wrapping += ".as_mut_ptr()"
        else:
            if arg["binding_type"].startswith("*const "):
                rust.wrapping += " as *const _"
            elif arg["binding_type"].startswith("*mut "):
                rust.wrapping += " as *mut _"
            if arg["is_mapped"] and wrapping_conf.get("map_types", "implicit") == "explicit":
                rust.wrapping += f" as {arg['binding_type']}"
        rust.wrapping += ",\n"
    rust.wrapping += "    ) };\n"
    if return_result:
        if wrapping_conf["return_as_result"] == "0 is Ok":
            rust.wrapping += "    if res != 0 {\n        return Err(());\n    }\n"
        else:
            raise ValueError(f"return_as_result has value {wrapping_conf['return_as_result']} which wasn't expected")

    if wrapping_return:
        if has_return and not return_result:
            assert len(uninit_mutate_init_return) == 0
            rust.wrapping += "    res\n"
        elif len(uninit_mutate_init_return) == 1:
            arg = args_lookup[uninit_mutate_init_return[0]]
            rust.wrapping += "    "
            if return_result:
                rust.wrapping += "Ok("
            rust.wrapping += f"unsafe {{ {arg['name']}.assume_init() }}"
            if return_result:
                rust.wrapping += ")"
            rust.wrapping += "\n"
        else:
            for arg_id in uninit_mutate_init_return:
                arg = args_lookup[arg_id]
                rust.wrapping += f"    let {arg['name']} = unsafe {{ {arg['name']}.assume_init() }};\n"
            rust.wrapping += "    "
            if return_result:
                rust.wrapping += "Ok("
            rust.wrapping += "("
            rust.wrapping += ", ".join([args_lookup[arg_id]["name"] for arg_id in uninit_mutate_init_return])
            rust.wrapping += ")"
            if return_result:
                rust.wrapping += ")"
            rust.wrapping += "\n"
    rust.wrapping += f"}}\n"

def main():
    with open("scripts/dilithium.json", 'r') as json_file:
        spec = json.load(json_file)
    with open("scripts/internal_ffi_api.json", 'r') as json_file:
        api = json.load(json_file)

    for param_set in spec["parameter_sets"]:
        level = param_set["security_level"]

        for impl in param_set["implementations"]:
            assert impl in ["clean", "avx2", "aarch64"]
            if impl == "avx2":
                continue
            impl_spec = Impl(level, impl)
            rust_code = Rust()

            rust_code.header += "//! Generated FFI bindings and wrapper functions.\n\n"
            rust_code.header += "//! This file is generated by `scripts/internal_ffi_bindings.py` from the FFI descriptions in `scripts/internal_ffi_api.json`. Do not edit manually!\n"
            rust_code.header += "use super::*;\n"
            rust_code.header += "use core::mem::MaybeUninit;\n"
            rust_code.binding += f"#[link(name = \"dilithium{level}_{impl}\")]\n"
            rust_code.binding += f"extern \"C\" {{"

            for function in api["api"]:
                if "wrappings" in function:
                    wrappings = function["wrappings"]
                elif "wrapping" in function:
                    wrappings = [function["wrapping"]]
                else:
                    wrappings = [{}]
                first = True
                for wrapping_conf in wrappings:
                    process_function_wrapping(rust_code, function, wrapping_conf, impl_spec, first)
                    first = False

            rust_code.binding += f"}}\n"

            with open(f"src/internals/dilithium{level}/{impl}/ffi.rs", 'w') as rust_file:
                rust_file.write(rust_code.header)
                rust_file.write("\n")
                rust_file.write(rust_code.binding)
                rust_file.write("\n")
                rust_file.write(rust_code.wrapping)
                rust_file.write("\n")

if __name__ == "__main__":
    main()
