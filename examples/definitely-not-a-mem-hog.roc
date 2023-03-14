app "definitely-not-a-mem-hog"
    packages { pf: "../src/main.roc" }
    imports [pf.Stdout, pf.Task.{ Task }]
    provides [main] to pf

main : Task {} []
main =
    # is this too wasteful for hello world? I just want 10MB.
    cap = 10
    capStr = Num.toStr cap

    Str.withCapacity (cap * 1024 * 1024)
    |> Str.concat "Hello, World!\nThis Str has a capacity of \(capStr) MB!"
    |> Stdout.line

