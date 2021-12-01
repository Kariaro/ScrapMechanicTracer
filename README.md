# Scrap Mechanic lua API

## Documentation Webpage (New)
All function information and official documentation has been combined into a documentation webpage:
https://gamedocs.github.io/

## Info
This plugin was made for Ghidra 9.2 and uses java 15.0.1.

This plugin loads all lua functions inside of the game Scrap Mechanic and tries to figure
out the parameters and return types for each function.

All this data is then saved to a file that can be further exported into other output types.
Here are some example on how the traces will look: [Examples](../master/res/traces).

What this plugin does is to search for all values inside the global table **sm** and trying to
understand the code flow of each function to reverseengineer the call stack.

*This plugin has been tested and works with the versions (0.4.0 - 0.4.8)*


## Pre made traces

I've run some traces before and they can be used to find specific functions for a modding idea.
[Traces](../master/res/traces).


## Documentation

No function will contain information about what it does but it will tell you the parameters
and sandbox it uses.

The parameters will make it easier to use undocumented functions and make some mods possible
by knowing this information.


## Usage

When using this plugin you first need to import the executable for ScrapMechanic into ghidra.
Make sure that you do not do any analysis on the executable before you use it.
*(Using Auto Analysis could 30 or more minutes)*

Press the blue Scrap Mechanic icon and select the about of threads and the depth you want to search.
*(The recomended search depth is 2)*

Press **Scan** and wait for the scan to finish. When the scan is finished it will create a popup 
that tells you that it's done you can then press the button "Open Save Path" where you will find
the trace.

If you want a more redable version of the trace you can press the tab **Export** and open the trace
you just made. Then you press **Export Simple** and you will now have a trace looking like the ones
inside the traces folder


## Installing

Install the zip file inside the release and open Ghidra.
Inside ghidra press the menu item *File* and press *Install Extensions...*.
Press the green button and find the downloaded zip file and add it. 
