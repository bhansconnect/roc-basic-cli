app "definitely-not-a-mem-hog"
    packages { pf: "../src/main.roc" }
    imports [pf.Stdout, pf.Task.{ Task }]
    provides [main] to pf

main : Task {} []
main =
    # is this too wasteful for hello world? I just want 10MB.
    cap = 10 * 1024 * 1024
    capStr = Num.toStr cap

    Str.withCapacity cap
    |> Str.concat "Hello, World!\nThis Str has a capacity of \(capStr) bytes!"
    |> Stdout.line

