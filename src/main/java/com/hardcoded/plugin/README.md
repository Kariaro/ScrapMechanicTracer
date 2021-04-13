# Code

Using the gidra PCode system we can detect the parameters of each defined lua function.

TODO: Write more about how this plugin works.

ScrapMechanic stores all namespace functions in arrays such as this one and adds them with a call to `luaL_register`.

```cpp
// Body of the register call
static const luaL_reg LUA_TABLE[] = {
    { "getX", func_shape_get_x },
    { "getY", func_shape_get_y },
    { NULL, NULL }
};

// Registering the namespace
luaL_register(lvm, "sm.shapes", LUA_TABLE);
```