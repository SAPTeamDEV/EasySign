using static System.IO.Path;

namespace SAPTeam.EasySign.UnifiedPath
{
    /// <summary>
    /// Represents an operating system path and provides methods for path conversion and manipulation.
    /// </summary>
    public class OSPath
    {
        /// <summary>
        /// Represents an empty OSPath.
        /// </summary>
        public static readonly OSPath Empty = "";

        /// <summary>
        /// Gets a value indicating whether the current operating system is Windows.
        /// </summary>
        public static bool IsWindows => DirectorySeparatorChar == '\\';

        /// <summary>
        /// Initializes a new instance of the <see cref="OSPath"/> class with the specified text.
        /// </summary>
        /// <param name="text">The path text.</param>
        public OSPath(string text) => Text = text.Trim();

        /// <summary>
        /// Implicitly converts a string to an <see cref="OSPath"/>.
        /// </summary>
        /// <param name="text">The path text.</param>
        public static implicit operator OSPath(string text) => new OSPath(text);

        /// <summary>
        /// Implicitly converts an <see cref="OSPath"/> to a string.
        /// </summary>
        /// <param name="path">The OSPath instance.</param>
        public static implicit operator string(OSPath path) => path.Normalized;

        /// <inheritdoc/>
        public override string ToString() => Normalized;

        /// <summary>
        /// Gets the original path text.
        /// </summary>
        protected string Text { get; }

        /// <summary>
        /// Gets the normalized path based on the current operating system.
        /// </summary>
        public string Normalized => IsWindows ? Windows : Unix;

        /// <summary>
        /// Gets the Windows-style path.
        /// </summary>
        public string Windows => Text.Replace('/', '\\');

        /// <summary>
        /// Gets the Unix-style path.
        /// </summary>
        public string Unix => Simplified.Text.Replace('\\', '/');

        /// <summary>
        /// Gets the path without the root or drive letter.
        /// </summary>
        public OSPath Relative => Simplified.Text.TrimStart('/', '\\');

        /// <summary>
        /// Gets a value indicating whether the path is absolute.
        /// </summary>
        public bool IsAbsolute => IsRooted || HasVolume;

        /// <summary>
        /// Gets a value indicating whether the path is rooted.
        /// </summary>
        public bool IsRooted => Text.Length >= 1 && (Text[0] == '/' || Text[0] == '\\');

        /// <summary>
        /// Gets a value indicating whether the path has a drive letter.
        /// </summary>
        public bool HasVolume => Text.Length >= 2 && Text[1] == ':';

        /// <summary>
        /// Gets the rooted path without the drive letter.
        /// </summary>
        public OSPath Simplified => HasVolume ? Text.Substring(2) : Text;

        /// <summary>
        /// Gets the parent directory of the path.
        /// </summary>
        public OSPath Parent
        {
            get
            {
                var parent = GetDirectoryName(Text);

                if (parent == null)
                {
                    var root = GetPathRoot(Text);

                    if (root == null)
                    {
                        return Empty;
                    }

                    return root;
                }

                return parent;
            }
        }

        /// <summary>
        /// Determines whether the current path contains the specified path.
        /// </summary>
        /// <param name="path">The path to check.</param>
        /// <returns><c>true</c> if the current path contains the specified path; otherwise, <c>false</c>.</returns>
        public bool Contains(OSPath path) => Normalized.StartsWith(path);

        /// <summary>
        /// Concatenates two paths.
        /// </summary>
        /// <param name="left">The left path.</param>
        /// <param name="right">The right path.</param>
        /// <returns>The concatenated path.</returns>
        public static OSPath operator +(OSPath left, OSPath right) =>
            new OSPath(Combine(left, right.Relative));

        /// <summary>
        /// Removes the specified path from the current path.
        /// </summary>
        /// <param name="left">The current path.</param>
        /// <param name="right">The path to remove.</param>
        /// <returns>The resulting path after removal.</returns>
        public static OSPath operator -(OSPath left, OSPath right) =>
            left.Contains(right)
            ? new OSPath(left.Normalized.Substring(right.Normalized.Length)).Relative
            : left;
    }
}
