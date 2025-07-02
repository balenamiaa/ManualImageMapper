namespace ManualImageMapper;

public static class LevenshteinDistance
{
    /// <summary>
    /// Calculates the Levenshtein distance between two strings.
    /// This is the minimum number of single-character edits (insertions, deletions, or substitutions)
    /// required to change one string into the other.
    /// This implementation is clear but uses O(n*m) space.
    /// </summary>
    /// <param name="source">The source string.</param>
    /// <param name="target">The target string.</param>
    /// <returns>The Levenshtein distance.</returns>
    public static int Calculate(string source, string target)
    {
        // Handle null or empty strings
        if (string.IsNullOrEmpty(source))
        {
            return string.IsNullOrEmpty(target) ? 0 : target.Length;
        }
        if (string.IsNullOrEmpty(target))
        {
            return source.Length;
        }

        int n = source.Length;
        int m = target.Length;

        // The distance matrix. d[i, j] will hold the distance between
        // the first i characters of source and the first j characters of target.
        int[,] distance = new int[n + 1, m + 1];

        // --- Step 1: Initialization ---
        // The distance of any first string to an empty second string is the number of deletions
        for (int i = 0; i <= n; i++)
        {
            distance[i, 0] = i;
        }

        // The distance of any second string to an empty first string is the number of insertions
        for (int j = 0; j <= m; j++)
        {
            distance[0, j] = j;
        }

        // --- Step 2: Fill the matrix ---
        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                // Cost of substitution is 0 if characters are the same, 1 otherwise
                int cost = (target[j - 1] == source[i - 1]) ? 0 : 1;

                // --- Step 3: Find the minimum cost ---
                // Three possible operations to consider:
                // 1. Deletion from source: distance[i - 1, j] + 1
                // 2. Insertion into source: distance[i, j - 1] + 1
                // 3. Substitution:         distance[i - 1, j - 1] + cost
                int deletionCost = distance[i - 1, j] + 1;
                int insertionCost = distance[i, j - 1] + 1;
                int substitutionCost = distance[i - 1, j - 1] + cost;

                distance[i, j] = Math.Min(Math.Min(deletionCost, insertionCost), substitutionCost);
            }
        }

        // --- Step 4: The final distance ---
        // The distance is in the bottom-right cell of the matrix
        return distance[n, m];
    }
}