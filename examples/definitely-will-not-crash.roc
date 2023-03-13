app "definitely-will-not-crash"
    packages { pf: "../src/main.roc" }
    imports [pf.Stdin, pf.Stdout, pf.Task.{ await, Task }]
    provides [main] to pf

main : Task {} []
main =
    Task.loop {} \_ -> 
        res <- tick |> Task.attempt
        when res is
            Ok _ ->
                Task.succeed (Step {})
            Err _ ->
                Task.succeed (Done {})

tick =
    _ <- await (Stdout.line "Input a number:")
    number <- Stdin.line |> await
    when Str.toI8 number is
        Ok n ->
            out = Num.toStr (n + 1)
            Stdout.line "Your number plus 1 is \(out)\n"
        Err _ ->
            crash "Why didn't you enter a number that fit in an i8?"
