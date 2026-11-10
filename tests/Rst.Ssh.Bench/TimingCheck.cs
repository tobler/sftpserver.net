using System.Diagnostics;
using Rst.Ssh.Internal;
public static class TimingCheck {
  // Rough timing check (dudect-style): scalars with almost only 0 bits vs. almost only 1 bits, measured alternately.
  public static void Run() { Measure("new (constant-time)", (k,u)=>X25519.ScalarMult(k,u)); Measure("old (BigInteger)", (k,u)=>BenchRef.X25519Reference.ScalarMult(k,u)); }
  static void Measure(string name, System.Func<byte[],byte[],byte[]> f) {
    var u = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    var low = new byte[32]; var high = System.Linq.Enumerable.Repeat((byte)0xff, 32).ToArray();
    var tl = new List<double>(); var th = new List<double>();
    for (var i = 0; i < 50; i++) { f(low, u); f(high, u); }
    for (var i = 0; i < 1000; i++) {
      var sw = Stopwatch.StartNew(); f(low, u); tl.Add(sw.Elapsed.TotalMicroseconds);
      sw.Restart(); f(high, u); th.Add(sw.Elapsed.TotalMicroseconds);
    }
    double Med(List<double> l) { var s = l.Order().ToList(); return s[s.Count / 2]; }
    System.Console.WriteLine($"{name,-22} median few bits: {Med(tl):F1} µs, many bits: {Med(th):F1} µs, difference {(Med(th)-Med(tl))/Med(tl)*100:F2} %");
  }
}
