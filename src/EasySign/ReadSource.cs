namespace SAPTeam.EasySign
{
    /// <summary>
    /// Specifies the source from which to read the data.
    /// </summary>
    public enum ReadSource
    {
        /// <summary>
        /// Read from both the bundle and the disk.
        /// </summary>
        Both,

        /// <summary>
        /// Read from the bundle.
        /// </summary>
        Bundle,

        /// <summary>
        /// Read from the disk.
        /// </summary>
        Disk
    }
}
