using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EasySign
{
    public class Signature
    {
        public Dictionary<string, byte[]> Entries { get; set; } = new();
    }
}
