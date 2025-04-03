namespace SAPTeam.EasySign.UnifiedPath
{
    /// <summary>
    /// Represents a folder in the file system and provides methods to interact with it.
    /// </summary>
    public class Folder : FolderEntry
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Folder"/> class with the specified full path.
        /// </summary>
        /// <param name="fullPath">The full path of the folder.</param>
        public Folder(OSPath fullPath)
            : this(fullPath, OSPath.Empty)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Folder"/> class with the specified full path and root path.
        /// </summary>
        /// <param name="fullPath">The full path of the folder.</param>
        /// <param name="root">The root path of the folder.</param>
        public Folder(OSPath fullPath, OSPath root)
            : base(fullPath, root)
        {
        }

        /// <summary>
        /// Returns a new <see cref="Folder"/> instance with the current folder as the root.
        /// </summary>
        /// <returns>A new <see cref="Folder"/> instance.</returns>
        public Folder AsRoot() => new Folder(FullPath, FullPath);

        /// <summary>
        /// Returns a new <see cref="Folder"/> instance representing the parent directory.
        /// </summary>
        /// <returns>A new <see cref="Folder"/> instance.</returns>
        public Folder Up() =>
            new Folder(FullPath.Parent, Root);

        /// <summary>
        /// Returns a new <see cref="Folder"/> instance representing a subdirectory.
        /// </summary>
        /// <param name="folder">The name of the subdirectory.</param>
        /// <returns>A new <see cref="Folder"/> instance.</returns>
        public Folder Down(string folder) =>
            new Folder(FullPath + folder, Root);

        /// <summary>
        /// Gets a value indicating whether the folder exists.
        /// </summary>
        public bool Exists =>
            Directory.Exists(FullPath);

        /// <summary>
        /// Creates the folder if it does not already exist.
        /// </summary>
        public void Create() =>
            Directory.CreateDirectory(FullPath);

        /// <summary>
        /// Returns a <see cref="FolderFile"/> instance representing a file in the folder.
        /// </summary>
        /// <param name="path">The relative path of the file.</param>
        /// <returns>A <see cref="FolderFile"/> instance.</returns>
        public FolderFile File(OSPath path) =>
            new FolderFile(FullPath + path, Root);

        /// <summary>
        /// Enumerates the subdirectories of the folder.
        /// </summary>
        /// <returns>An enumerable collection of <see cref="Folder"/> instances representing the subdirectories.</returns>
        public IEnumerable<Folder> Folders() =>
            from fullPath in Directory.EnumerateDirectories(FullPath)
            select new Folder(fullPath, Root);

        /// <summary>
        /// Enumerates the files in the folder.
        /// </summary>
        /// <returns>An enumerable collection of <see cref="FolderFile"/> instances representing the files.</returns>
        public IEnumerable<FolderFile> Files() =>
            from fullPath in Directory.EnumerateFiles(FullPath)
            select new FolderFile(fullPath, Root);
    }
}
