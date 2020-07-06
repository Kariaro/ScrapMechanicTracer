# ScrapMechanicTracer

This is a plugin for ghidra and was created to make modding easier for the game ScrapMechanic.
Because most commands are not documented this plugin was made to get all the function arguments
and to dump them to a readable file. Here are some example on how the traces will look: [Examples](../master/res/traces).

What this plugin does is to search for all values inside the global table **sm** and trying to
understand the code flow of each function to reverseengineer the call stack.

This plugin is aimed to work on every version of ScrapMechanic without any problems. (Tested 0.4.0 - 0.4.6)

## Installing

TODO




## Usage
Specify the amount of threads you want the analyser to use and the maximum depth it's allowed to search.
After that you press **Scan** and it will dump the trace to the selected **Trace Save Path**.