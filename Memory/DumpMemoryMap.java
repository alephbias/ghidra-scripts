//Export memory map information from Ghidra
//@Aleph
//@category Memory

import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;

public class DumpMemoryMap extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        File outputFile = askFile("Select Output File", "Save");
        
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            // Write header
            writer.println("Name,Start,End,Size,R,W,X,Volatile,Type");
            
            // Process each memory block
            for (MemoryBlock block : memory.getBlocks()) {
                String line = String.format("%s,0x%X,0x%X,%d,%s,%s,%s,%s,%s",
                    block.getName(),
                    block.getStart().getOffset(),
                    block.getEnd().getOffset(),
                    block.getSize(),
                    block.isRead() ? "1" : "0",
                    block.isWrite() ? "1" : "0",
                    block.isExecute() ? "1" : "0",
                    block.isVolatile() ? "1" : "0",
                    block.getType()
                );
                writer.println(line);
            }
        }
        
        println("Memory map exported to: " + outputFile.getAbsolutePath());
    }
}
