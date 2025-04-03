namespace SAPTeam.EasySign.UnifiedPath
{

    /// <summary>
    /// Represents an abstract base class for folder entries.
    /// </summary>
    public abstract class FolderEntry
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="FolderEntry"/> class.
        /// </summary>
        /// <param name="fullPath">The full path of the folder entry.</param>
        /// <param name="root">The root path of the folder entry.</param>
        protected FolderEntry(OSPath fullPath, OSPath root)
        {
            FullPath = fullPath;
            Root = root;
        }

        /// <summary>
        /// Gets the full path of the folder entry.
        /// </summary>
        public OSPath FullPath { get; }

        /// <summary>
        /// Gets the relative path of the folder entry from the root.
        /// </summary>
        public OSPath Path => FullPath - Root;

        /// <summary>
        /// Gets the root path of the folder entry.
        /// </summary>
        protected OSPath Root { get; }
    }
}
