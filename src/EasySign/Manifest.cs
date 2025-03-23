using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SAPTeam.EasySign
{
    public class Manifest
    {
        private ConcurrentDictionary<string, byte[]> entries = new ConcurrentDictionary<string, byte[]>();

        public SortedDictionary<string, byte[]> Entries
        {
            get
            {
                return new(entries);
            }
            set
            {
                entries = new(value);
            }
        }

        public bool BundleFiles { get; set; }

        public ConcurrentDictionary<string, byte[]> GetConcurrentDictionary() => entries;
    }
}
