try:
    import ida as idapro
except ImportError:
    import idapro
 
import os

import ida_nalt
import idaapi
import ida_funcs
import ida_typeinf
import idc
import idautils
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_xref
import ida_loader

import struct
from typing import Optional, TypedDict, Annotated

class Function(TypedDict):
    start_address: int
    end_address: int
    name: str
    prototype: Optional[str]

class IDAError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]

class Xref(TypedDict):
    address: int
    type: str
    function: Optional[Function]

class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str

class IDA():
    def __init__(self, binary_path: Annotated[str, "Path to the binary file"]):
        try:
            if not os.path.exists(binary_path):
                self.open = False
                print(f"Binary file does not exist: {binary_path}")
                return
            idapro.open_database(binary_path, True)
            self.open = True
        except Exception as e:
            self.open = False
            print(f"Failed to open database: {e}")

    def get_image_size(self):
        omax_ea = idaapi.inf_get_max_ea()
        omin_ea = idaapi.inf_get_min_ea()

        # Bad heuristic for image size (bad if the relocations are the last section)
        image_size = omax_ea - omin_ea
        # Try to extract it from the PE header
        header = idautils.peutils_t().header()
        if header and header[:4] == b"PE\0\0":
            image_size = struct.unpack("<I", header[0x50:0x54])[0]
        return image_size

    def get_prototype(self, fn: int) -> Optional[str]:
        try:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, fn):
                return str(tif)
            else:
                return None
        except Exception as e:
            return f"Error getting function prototype for function at address {fn}"

    def get_function(self, address: int, *, raise_error=True) -> Optional[dict]:
        fn = idaapi.get_func(address)
        if fn is None:
            if raise_error:
                return f"No function found at address {address}"
            else:
                return None

        try:
            name = fn.get_name()
        except AttributeError:
            name = ida_funcs.get_func_name(fn.start_ea)
        return {
            "address": fn.start_ea,
            "end_address": fn.end_ea,
            "name": name,
            "prototype": self.get_prototype(fn.start_ea),
        }

    def get_function_by_name(self, name: Annotated[str, "Name of the function to get"]) -> Optional[dict]:
        """Get a function by its name"""
        function_address = idaapi.get_name_ea(idaapi.BADADDR, name)
        if function_address == idaapi.BADADDR:
            return f"No function found with name {name}"
        return self.get_function(function_address)

    def get_function_by_address(self, address: Annotated[int, "Address of the function to get"]) -> Optional[dict]:
        """Get a function by its address"""
        return self.get_function(address)

    def get_current_address(self) -> int:
        """Get the address currently selected by the user"""
        return idaapi.get_screen_ea()

    def get_current_function(self) -> Optional[dict]:
        """Get the function currently selected by the user"""
        return self.get_function(idaapi.get_screen_ea())

    def convert_number(self, text: Annotated[str, "Textual representation of the number to convert"], 
                       size: Annotated[Optional[int], "Size of the variable in bytes"]) -> ConvertedNumber:
        """Convert a number (decimal, hexadecimal) to different representations"""
        try:
            value = int(text, 0)
        except ValueError:
            return f"Invalid number: {text}"
        
        # Estimate the size of the number
        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        # Convert the number to bytes
        try:
            bytes = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            return f"Number {text} is too big for {size} bytes"

        # Convert the bytes to ASCII
        ascii = ""
        for byte in bytes.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii += chr(byte)
            else:
                ascii = None
                break

        return {
            "decimal": str(value),
            "hexadecimal": hex(value),
            "bytes": bytes.hex(" "),
            "ascii": ascii,
            "binary": bin(value)
        }
    
    def list_functions(self) -> list[Function]:
        """List all functions in the database"""
        return [self.get_function(address) for address in idautils.Functions()]

    def decompile_checked(self, address: int):
        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-Rays decompiler is not available")
            return None
        
        error = ida_hexrays.hexrays_failure_t()
        cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(address, error, ida_hexrays.DECOMP_WARNINGS)
        if not cfunc:
            message = f"Decompilation failed at {address}"
            if error.str:
                message += f": {error.str}"
            if error.errea != idaapi.BADADDR:
                message += f" (address: {error.errea})"
            print(message)
            return None
        return cfunc

    
    def decompile_function(self, address: Annotated[int, "Address of the function to decompile"]) -> str:
        """Decompile a function at the given address"""
        cfunc = self.decompile_checked(address)
        if not cfunc:
            return f"Failed to decompile function at address {address}"
        
        sv = cfunc.get_pseudocode()
        pseudocode = ""
        for _, sl in enumerate(sv):
            sl: ida_kernwin.simpleline_t
            line = ida_lines.tag_remove(sl.line)
            if len(pseudocode) > 0:
                pseudocode += "\n"
            pseudocode += f"{line}"
        return pseudocode
    
    def disassemble_function(self, address: Annotated[int, "Address of the function to disassemble"]) -> str:
        """Get assembly code (address: instruction; comment) for a function"""
        func = idaapi.get_func(address)
        if not func:
            return f"No function found at address {address}" 

        disassembly = ""
        for address in idaapi.func_item_iterator_t(func):
            if len(disassembly) > 0:
                disassembly += "\n"
            disassembly += f"{address}: "
            disassembly += idaapi.generate_disasm_line(address, idaapi.GENDSM_REMOVE_TAGS)
            comment = idaapi.get_cmt(address, False)
            if not comment:
                comment = idaapi.get_cmt(address, True)
            if comment:
                disassembly += f"; {comment}"
        return disassembly
    
    def get_xrefs_to(self, address: Annotated[int, "Address to get cross references to"]) -> list[Xref]:
        """Get all cross references to the given address"""
        xrefs = []
        xref: ida_xref.xrefblk_t
        for xref in idautils.XrefsTo(address):
            xrefs.append({
                "address": xref.frm,
                "type": "code" if xref.iscode else "data",
                "function": self.get_function(xref.frm, raise_error=False),
            })
        return xrefs
    
    def get_entry_points(self) -> list[Function]:
        """Get all entry points in the database"""
        result = []
        for i in range(idaapi.get_entry_qty()):
            ordinal = idaapi.get_entry_ordinal(i)
            address = idaapi.get_entry(ordinal)
            func = self.get_function(address, raise_error=False)
            if func is not None:
                result.append(func)
        return result

    def set_decompiler_comment(self, address: Annotated[int, "Address in the function to set the comment for"], 
                               comment: Annotated[str, "Comment text (not shown in the disassembly)"]) -> str:
        """Set a comment for a given address in the function pseudocode"""

        # Reference: https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/
        # Check if the address corresponds to a line
        cfunc = self.decompile_checked(address)
        if cfunc is None:
            return f"Failed to decompile function at address {address}"
        # Special case for function entry comments
        if address == cfunc.entry_ea:
            idc.set_func_cmt(address, comment, True)
            cfunc.refresh_func_ctext()
            return "Comment set successfully"

        eamap = cfunc.get_eamap()
        if address not in eamap:
            return f"Failed to set comment at {address}"
        nearest_ea = eamap[address][0].ea

        # Remove existing orphan comments
        if cfunc.has_orphan_cmts():
            cfunc.del_orphan_cmts()
            cfunc.save_user_cmts()

        # Set the comment by trying all possible item types
        tl = idaapi.treeloc_t()
        tl.ea = nearest_ea
        for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
            tl.itp = itp
            cfunc.set_user_cmt(tl, comment)
            cfunc.save_user_cmts()
            cfunc.refresh_func_ctext()
            if not cfunc.has_orphan_cmts():
                return "Comment set successfully"
            cfunc.del_orphan_cmts()
            cfunc.save_user_cmts()
        return f"Failed to set comment at {address}"
    
    def set_disassembly_comment(self, address: Annotated[int, "Address in the function to set the comment for"], 
                                comment: Annotated[str, "Comment text (not shown in the pseudocode)"]):
        """Set a comment for a given address in the function disassembly"""
        if not idaapi.set_cmt(address, comment, False):
            return f"Failed to set comment at {address}"
        else:
            return "Comment set successfully"

    def refresh_decompiler_widget(self):
        widget = ida_kernwin.get_current_widget()
        if widget is not None:
            vu = ida_hexrays.get_widget_vdui(widget)
            if vu is not None:
                vu.refresh_ctext()
    
    def refresh_decompiler_ctext(self, function_address: int):
        error = ida_hexrays.hexrays_failure_t()
        cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(function_address, error, ida_hexrays.DECOMP_WARNINGS)
        if cfunc:
            cfunc.refresh_func_ctext()
    
    def rename_local_variable(self, function_address: Annotated[int, "Address of the function containing the variable"], 
                              old_name: Annotated[str, "Current name of the variable"], 
                              new_name: Annotated[str, "New name for the variable"]):
        """Rename a local variable in a function"""
        func = idaapi.get_func(function_address)
        if not func:
            return f"No function found at address {function_address}"
        
        if not ida_hexrays.rename_lvar(func.start_ea, old_name, new_name):
            return f"Failed to rename local variable {old_name} in function {func.start_ea}"
        
        self.refresh_decompiler_ctext(func.start_ea)
        return f"Local variable {old_name} renamed to {new_name} in function {func.start_ea}"

    def rename_function(self, function_address: Annotated[int, "Address of the function to rename"], 
                        new_name: Annotated[str, "New name for the function"]):
        """Rename a function"""
        fn = idaapi.get_func(function_address)
        if not fn:
            return f"No function found at address {function_address}"
        
        if not idaapi.set_name(fn.start_ea, new_name):
            return f"Failed to rename function {fn.start_ea} to {new_name}"
        
        self.refresh_decompiler_ctext(fn.start_ea)
        return f"Function {fn.start_ea} renamed to {new_name}"
    
    def set_function_prototype(self, function_address: Annotated[int, "Address of the function"], 
                               prototype: Annotated[str, "New function prototype"]) -> str:
        """Set a function's prototype"""
        fn = idaapi.get_func(function_address)
        if not fn:
            return f"No function found at address {function_address}"
        try:
            tif = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(tif, None, prototype, ida_typeinf.PT_SIL | ida_typeinf.PT_TYP)
            if not tif.is_func():
                return f"Parsed declaration is not a function type"
            elif not ida_typeinf.apply_tinfo(fn.start_ea, tif, ida_typeinf.PT_SIL):
                return f"Failed to apply type"
            
            self.refresh_decompiler_ctext(fn.start_ea)
            return f"Function prototype set successfully"
        except Exception as e:
            return f"Failed to parse prototype string: {prototype}"
        
    def save_idb_file(self, save_path: Annotated[str, "Path to save the IDB file"]):
        ida_loader.save_database(save_path, 0)
    
    def clean_up(self, save_db = False):
        if self.open:
            idapro.close_database(save_db)
