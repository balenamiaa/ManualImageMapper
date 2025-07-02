using ManualImageMapper;

var commandLineArgs = Environment.GetCommandLineArgs();

// if (commandLineArgs.Length != 2)
// {
//     Console.WriteLine("Usage: BINARY <image path> <process identifier>");
//     return;
// }

// var path = commandLineArgs[1];
// var pid = commandLineArgs[2];



var test = GetPiD.FromProcessName("msedge");
Console.WriteLine(test);