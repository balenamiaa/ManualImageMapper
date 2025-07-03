namespace ManualImageMapper.StringMatching;

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
        if (string.IsNullOrEmpty(source))
            return string.IsNullOrEmpty(target) ? 0 : target.Length;
        if (string.IsNullOrEmpty(target))
            return source.Length;

        int n = source.Length;
        int m = target.Length;

        int[,] distance = new int[n + 1, m + 1];

        for (int i = 0; i <= n; i++)
        {
            distance[i, 0] = i;
        }

        for (int j = 0; j <= m; j++)
        {
            distance[0, j] = j;
        }

        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                int cost = (target[j - 1] == source[i - 1]) ? 0 : 1;

                int deletionCost = distance[i - 1, j] + 1;
                int insertionCost = distance[i, j - 1] + 1;
                int substitutionCost = distance[i - 1, j - 1] + cost;

                distance[i, j] = Math.Min(Math.Min(deletionCost, insertionCost), substitutionCost);
            }
        }

        return distance[n, m];
    }
}