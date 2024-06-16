\contentsline {lstlisting}{\numberline {2.1}A function which adds an integer value \lstinline [mathescape]{v} to the end of a linked list.}{11}{lstlisting.2.1}%
\contentsline {lstlisting}{\numberline {2.2}Ghidra decompilation of the code presented in Listing \ref {code:decompilation-original}. The decompilation is take as-is and has not modified in any way.}{11}{lstlisting.2.2}%
\contentsline {lstlisting}{\numberline {2.3}Ghidra decompilation of the code presented in Listing \ref {code:decompilation-original}. The decompilation has been modified by renaming variabled and changing data types, based on educated guesses.}{11}{lstlisting.2.3}%
\contentsline {lstlisting}{\numberline {2.4}ltrace (``a library call tracer'') output of an obfuscated crackme. One can observe a length check in the first execution, and different output when an input of the expected length is provided.}{13}{lstlisting.2.4}%
\contentsline {lstlisting}{\numberline {2.5}A trivial code example of a function taking a one-byte argument and having different output to \lstinline [mathescape]{stdout}, based on that argument. The example is meant to showcase \gls {SE}. A visual representation of symbolically executing this piece of code can be seen in Figure \ref {fig:se}.}{14}{lstlisting.2.5}%
\contentsline {lstlisting}{\numberline {4.1}Decompilation section of the \lstinline [mathescape]{vmwhere} dispatcher, after variable renaming and retyping. We notice the implementation of the \lstinline [mathescape]{add}, \lstinline [mathescape]{jlz} and \lstinline [mathescape]{push_top} instructions.}{22}{lstlisting.4.1}%
\contentsline {lstlisting}{\numberline {4.2}x86\_64 disassembly of the \lstinline [mathescape]{vmcastle} dispatcher. The function handler corresponding to the current opcode is indirectly called through the register \lstinline [mathescape]{RDX}.}{23}{lstlisting.4.2}%
\contentsline {lstlisting}{\numberline {4.3}Stack-based implementation of a simple \lstinline [mathescape]{add} instruction in the \lstinline [mathescape]{vmwhere} architecture.}{24}{lstlisting.4.3}%
\contentsline {lstlisting}{\numberline {4.4}Register-based implementation of a simple \lstinline [mathescape]{add} instruction in the \lstinline [mathescape]{vmcastle} architecture.}{24}{lstlisting.4.4}%
\contentsline {lstlisting}{\numberline {4.5}Partial result of symbolically executing a function handler in Miasm. One will notice the state change in core registers such as \lstinline [mathescape]{RDX}, flag changes, as well as changes in memory.}{24}{lstlisting.4.5}%
\contentsline {lstlisting}{\numberline {4.6}Result of symbolically executing the same function handler as in Listing \ref {lst:miasm0} with some cleanup. We only chose to display the change in relevant registers and memory locations. Additionally, we introduced labels for better clarity.}{25}{lstlisting.4.6}%
\contentsline {lstlisting}{\numberline {4.7}A minimal angr code sample. We load a program into \lstinline [mathescape]{p}, create a simulation manager, symbolically execute the program until we reach the desired address \lstinline [mathescape]{0xcafebabe}, and finally print the input which determined this execution path.}{28}{lstlisting.4.7}%
\contentsline {lstlisting}{\numberline {4.8}TODO}{29}{lstlisting.4.8}%
\contentsline {lstlisting}{\numberline {4.9}TODO}{30}{lstlisting.4.9}%
\contentsline {lstlisting}{\numberline {4.10}TODO}{32}{lstlisting.4.10}%
\contentsline {lstlisting}{\numberline {4.11}TODO}{32}{lstlisting.4.11}%
\contentsline {lstlisting}{\numberline {4.12}TODO}{33}{lstlisting.4.12}%
\contentsline {lstlisting}{\numberline {4.13}TODO}{35}{lstlisting.4.13}%
\contentsline {lstlisting}{\numberline {4.14}TODO}{39}{lstlisting.4.14}%
\contentsline {lstlisting}{\numberline {4.15}TODO}{39}{lstlisting.4.15}%
