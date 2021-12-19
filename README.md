# RunPeInMemory
Example of using the process hollowing technique.  
The application runs the target 32-bit executable in memory of the victim's 32-bit executable.

### Principle of operation:
---

* decrypt target PE from resources;
* start the victim process in a suspended state;
* allocate memory within the victim to place the target;
* transfer target sections to allocated memory;
* apply relocations for the new base address;
* resume the victim process.

---
