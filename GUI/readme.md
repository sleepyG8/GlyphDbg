This is the GUI for GlyphDbg... It is an extention and is not needed. I prefer the commandline version but a gui windows helps with multi tasking and traversing large dumps.

To run the GUI, make sure the actualy Glyph.exe engine is compiled and inside the same directory as the GUI exe. This is because the GUI actually starts up the engine in -api mode.
Next after having the GUI and engine together and any other extentions you want to include, run "glyphGui.exe Notepad.exe". 

Right now the engine supports only connecting to processes, but with some tweaks and another api function. there will be starting of processes supported.
