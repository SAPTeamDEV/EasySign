namespace SAPTeam.EasySign.UnifiedPath
{
    /// <summary>
    /// Represents a file within a folder in the unified path system.
    /// </summary>
    public class FolderFile : FolderEntry
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="FolderFile"/> class with the specified full path.
        /// </summary>
        /// <param name="fullPath">The full path of the file.</param>
        public FolderFile(OSPath fullPath)
            : this(fullPath, OSPath.Empty)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="FolderFile"/> class with the specified full path and root path.
        /// </summary>
        /// <param name="fullPath">The full path of the file.</param>
        /// <param name="root">The root path of the file.</param>
        public FolderFile(OSPath fullPath, OSPath root)
            : base(fullPath, root)
        {
        }

        /// <summary>
        /// Gets a value indicating whether the file exists at the specified path.
        /// </summary>
        public bool Exists => File.Exists(FullPath);
    }
}
