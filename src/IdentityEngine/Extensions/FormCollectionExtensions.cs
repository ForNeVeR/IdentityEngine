using System.Collections;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace IdentityEngine.Extensions;

public static class FormCollectionExtensions
{
    public static IReadOnlyDictionary<string, StringValues> AsReadOnlyDictionary(this IFormCollection formCollection)
    {
        ArgumentNullException.ThrowIfNull(formCollection);
        return new FormCollectionReadOnlyDictionary(formCollection);
    }

    private class FormCollectionReadOnlyDictionary : IReadOnlyDictionary<string, StringValues>
    {
        private readonly IFormCollection _formCollection;

        public FormCollectionReadOnlyDictionary(IFormCollection formCollection)
        {
            _formCollection = formCollection;
        }

        IEnumerator<KeyValuePair<string, StringValues>> IEnumerable<KeyValuePair<string, StringValues>>.GetEnumerator()
        {
            return _formCollection.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return _formCollection.GetEnumerator();
        }

        public int Count =>
            _formCollection.Count;

        public bool ContainsKey(string key)
        {
            return _formCollection.ContainsKey(key);
        }

        public bool TryGetValue(string key, out StringValues value)
        {
            return _formCollection.TryGetValue(key, out value);
        }

        public StringValues this[string key] =>
            _formCollection[key];

        public IEnumerable<string> Keys =>
            _formCollection.Keys;

        public IEnumerable<StringValues> Values =>
            throw new NotImplementedException();
    }
}
