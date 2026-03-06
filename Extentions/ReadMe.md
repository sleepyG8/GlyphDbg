## ioctlScan.dll

Run with !ext command

This grabs all running drivers and scans for possible IOCTL calls, this is great for hunting down vulnerablities in drivers.

## wor.exe

Run with the !wor commnd

This is a full object namespace walker

It takes in a first parameter as a object directory path (Ex: \Device) and enumerates all of the entries withing the given directory.

The second "optional" parameter is either a harddisk or a shadowcopy to walk, it also can restore deleted files if your ever in a pinch with the copy command.

## entropyCheck.dll

If in the debuggers directory it gives a shannon entropy rating 1-8 when !dump is ran

## staticDisasm.dll

Reads a file from disk and disassembles its .text section, run !static


## Notes.exe

Notepad for storing anything you want during a debugging session

## Kratos.exe

PE builder, can build full runnable PEs from memory

## rsrcWalker.dll

Walks the PE resource directory from disk. the source can be found under the rsrc directory here.

## bridge 

This program injects a breakpoint handler. It is needed internally by the engine to set breakpoints.
You must move this into your current working directory, wherever glyphs running, to set breakpoints.

## break

This is the handler. I will use this for other things in the future but for now it exclusively sets a
breakpoint handler. It is needed for breakpoints. Make sure to move this to the current working dir.
