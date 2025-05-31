# Simple ANSI string finder for Ghidra 11.x. Can be used to convert raw bytes that start with 
# ANSI escape code into strings Ghidra understands. For example, a string starting with 0x1B 0x5B 
# and then printable ASCII will change how the text looks in Bash. 
# But Ghidra won't recognize that, so this script looks for that pattern and changes the raw bytes to be strings.
# 
# Has not been thoroughly tested.
# @author Aleph Claude
# @category Strings
# @keybinding 
# @menupath 
# @toolbar 

from ghidra.program.model.data import TerminatedStringDataType
from ghidra.program.model.address import AddressRange

def scan_memory_block(block, memory):
    """Scan a memory block for ANSI strings"""
    strings_found = 0
    start = block.getStart()
    end = block.getEnd()
    
    # Work through the block byte by byte
    current = start
    
    while current.compareTo(end) < 0 and not monitor.isCancelled():
        try:
            # Check if already defined
            if getDataAt(current) is not None:
                current = current.add(1)
                continue
                
            # Check for ESC character
            byte_val = memory.getByte(current)
            if byte_val == 0x1B:  # ESC
                # Check for [
                next_byte = memory.getByte(current.add(1))
                if next_byte == 0x5B:  # [
                    # Looks like ANSI escape, find end of string
                    length = 0
                    while length < 1024:
                        b = memory.getByte(current.add(length))
                        if b == 0:
                            break
                        length += 1
                    
                    if length > 4:  # Minimum viable ANSI string
                        # Create the string
                        clearListing(current, current.add(length))
                        createData(current, TerminatedStringDataType.dataType)
                        
                        data = getDataAt(current)
                        if data and data.hasStringValue():
                            strings_found += 1
                            print("Found ANSI string at {}: {}".format(
                                current, repr(str(data.getValue())[:60])))
                            
                            # Skip past this string
                            current = current.add(length + 1)
                            continue
                            
        except Exception as e:
            pass
            
        current = current.add(1)
    
    return strings_found

def main():
    """Main function"""
    print("Scanning for ANSI escape code strings...")
    
    memory = currentProgram.getMemory()
    total_strings = 0
    
    # Process each initialized memory block
    for block in memory.getBlocks():
        if block.isInitialized() and not block.isOverlay():
            print("Scanning block: {} ({} - {})".format(
                block.getName(), block.getStart(), block.getEnd()))
            
            monitor.setMessage("Scanning " + block.getName())
            strings_in_block = scan_memory_block(block, memory)
            total_strings += strings_in_block
            
            if strings_in_block > 0:
                print("  Found {} strings in this block".format(strings_in_block))
    
    print("\nTotal ANSI strings found and converted: {}".format(total_strings))

# Run it
main()
