-module(server).
-export([server_loop/0, add/2, reverse/1, list_sum/1]).


reverse([], Res) -> Res;
reverse([H|T], PR) ->
    reverse(T, [H|PR]).

reverse(L) -> reverse(L, []).

list_sum([], Res) -> Res;
list_sum([H|T], PR) ->
    list_sum(T, PR + H).

list_sum(L) -> list_sum(L, 0).

list_count([], Res) -> Res;
list_count([_|T], PR) ->
    list_count(T, PR + 1).

list_count(L) -> list_count(L, 0).

server_loop() ->
    receive
        { From, { double, Number }} -> From ! {self(), Number*2},
                                       server_loop();
        { From, { reverse, List }} -> From ! {self(), reverse(List)},
                                      server_loop();
        { From, { count, List }} -> From ! {self(), list_count(List)},
                                    server_loop();
        { From, { sum, List }} -> From ! {self(), list_sum(List)},
                                  serverl_loop();
        { From, _ } -> From ! { self(), error },
                       server_loop()
    end.

add(X, Y) ->
    X + Y.
