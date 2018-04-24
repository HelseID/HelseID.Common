using System.Collections.Generic;

namespace HelseId.Common.Extensions
{
    public static class StringExtensions
    {
        public static bool IsNotNullOrEmpty(this string text)
        {
            return !string.IsNullOrEmpty(text);
        }

        public static bool IsNullOrEmpty(this string text)
        {
            return string.IsNullOrEmpty(text);
        }

        public static string[] FromSpaceSeparatedToList(this string spaceSeparatedList)
        {
            return spaceSeparatedList.Split(' ');
        }

        public static string ToSpaceSeparatedList(this List<string> list)
        {
            return string.Join(" ", list);
        }

        public static string ToSpaceSeparatedList(this string[] list)
        {
            return string.Join(" ", list);
        }
    }
}