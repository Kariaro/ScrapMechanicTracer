# Scrap Mechanic Tracer & API Documentation

This is a plugin for ghidra and was created to make modding easier for the game Scrap Mechanic.
Because most commands are not documented this plugin was made to get all the function arguments
and to dump them to a readable file. Here are some example on how the traces will look: [Examples](../master/res/traces).

What this plugin does is to search for all values inside the global table **sm** and trying to
understand the code flow of each function to reverseengineer the call stack.

This plugin is aimed to work on every version of ScrapMechanic without any problems. (Tested 0.4.0 - 0.4.8.620)


## Pre made traces

I've run some traces before and they can be used to find specific functions for a modding idea.
[Traces](../master/res/traces).


## Usage
Specify the amount of threads you want the analyser to use and the maximum depth it's allowed to search.
After that you press **Scan** and it will dump the trace to the selected **Trace Save Path**.


## Installing & Soon will maybe* add more images and make this doc better. 

Kinda done. Finishing up the project.

