import 
    os, 
    osproc,
    sequtils, 
    strformat,
    std/[
        strutils,
        terminal
    ]

# Echo the warning output of a PUA file
proc echoWarning ( file, positiveRule : string ) : void = 
    stdout.styledWriteLine(
        fgRed, 
        styleBright, 
        fmt"[WARNING!] Path {file} may contain malitious bytes : {positiveRule}"
    )

# Running a shell comand
proc runShellCommand *( command : string ) : void = 
    discard execCmd(command)

# Return the files from a path
proc fileList ( path : string ) : seq[string] =
    var list : seq[string] = @[] 
    for file in walkDir(path) : 
        add(list, file.path) 
    return list

# Transforming a string to a sequence
proc stringToSequence ( file : string ) : seq[string] = 
    return file.split().filterIt(it != "")

# Recursive procedure to find all the malitious files in the path 
proc runYaraRules( path: string, finalRules : seq[string] ) : void =  
    for file in walkDir(path) : 
        if file.kind == pcFile : 
            for rule in finalRules : 
                runShellCommand(fmt"yara {rule} {file.path} > positiverule")

                #Transforming the output in a sequence from the file
                let fileContent : string = readFile("positiverule")
                let seqContent : seq[string] = stringToSequence(fileContent)

                if seqContent.len > 0 : 
                    echoWarning(file.path, seqContent[0] & seqContent[1] & '\n')

        else : runYaraRules(file.path, finalRules)

# The main procedure
proc main() =
    var
        argument : string = paramStr(1) 
        rulesFolder : seq[string] = fileList(fmt"windows") 
        rules : seq[string] = @[]

    # Extracting the rules from your specific OS
    for folder in rulesFolder : 
        rules &= fileList(folder)

    runYaraRules(argument, rules)

when isMainModule : 
    main()
