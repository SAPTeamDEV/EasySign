namespace SAPTeam.EasySign
{
    /// <summary>
    /// Specifies the source from which to read the data.
    /// </summary>
    public enum ReadSource
    {
        /// <summary>
        /// Bundle decides the read source.
        /// </summary>
        /// <remarks>
        /// If the <see cref="Manifest.StoreOriginalFiles"/> property in the bundle is set to <see langword="true"/>, the data will be read from the bundle.
        /// </remarks>
        Automatic,

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
