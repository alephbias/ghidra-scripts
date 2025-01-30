//Import memory map information into Ghidra
//#@Aleph
//@category Memory

import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.mem.FileBytes;

public class ImportMemoryMap extends GhidraScript {

    @Override
    protected void run() throws Exception {
        DomainFile df = currentProgram.getDomainFile();
        if (df != null && df.isReadOnly()) {
            popup("Program must be checked out or private to modify memory map");
            return;
        }

        File inputFile = askFile("Select Memory Map CSV", "Import");
        
        try (BufferedReader reader = new BufferedReader(new FileReader(inputFile))) {
            // Skip header
            String header = reader.readLine();
            if (!header.startsWith("Name,Start,End,Size,R,W,X")) {
                popup("Invalid memory map file format");
                return;
            }

            Memory memory = currentProgram.getMemory();
            int transactionID = currentProgram.startTransaction("Import Memory Map");

            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(",");
                    if (parts.length < 8) continue;

                    String name = parts[0];
                    long start = Long.parseLong(parts[1].substring(2), 16); // Remove "0x" prefix
                    long end = Long.parseLong(parts[2].substring(2), 16);
                    long size = Long.parseLong(parts[3]);
                    boolean read = "1".equals(parts[4]);
                    boolean write = "1".equals(parts[5]);
                    boolean execute = "1".equals(parts[6]);
                    boolean isVolatile = "1".equals(parts[7]);

                    // Get the appropriate address space (default to RAM)
                    AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
                    Address startAddr = space.getAddress(start);
                    
                    // Remove existing block if it exists
                    MemoryBlock existing = memory.getBlock(startAddr);
                    if (existing != null) {
                        memory.removeBlock(existing, monitor);
                    }

                    // Create new memory block
                    try {
                        MemoryBlock block = memory.createUninitializedBlock(
                            name,
                            startAddr,
                            size,
                            false  // overlay
                        );

                        block.setRead(read);
                        block.setWrite(write);
                        block.setExecute(execute);
                        block.setVolatile(isVolatile);

                        println("Created block: " + name + " at " + startAddr);
                    }
                    catch (Exception e) {
                        println("Error creating block " + name + ": " + e.getMessage());
                    }
                }
            }
            finally {
                currentProgram.endTransaction(transactionID, true);
            }
        }
        
        println("Memory map import completed");
    }
}
