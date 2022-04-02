using System.Collections;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace IdentityEngine.Extensions;

public static class QueryCollectionExtensions
{
    public static IReadOnlyDictionary<string, StringValues> AsReadOnlyDictionary(this IQueryCollection queryCollection)
    {
        ArgumentNullException.ThrowIfNull(queryCollection);
        return new QueryCollectionReadOnlyDictionary(queryCollection);
    }

    private class QueryCollectionReadOnlyDictionary : IReadOnlyDictionary<string, StringValues>
    {
        private readonly IQueryCollection _queryCollection;

        public QueryCollectionReadOnlyDictionary(IQueryCollection queryCollection)
        {
            _queryCollection = queryCollection;
        }

        IEnumerator<KeyValuePair<string, StringValues>> IEnumerable<KeyValuePair<string, StringValues>>.GetEnumerator()
        {
            return _queryCollection.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return _queryCollection.GetEnumerator();
        }

        public int Count =>
            _queryCollection.Count;

        public bool ContainsKey(string key)
        {
            return _queryCollection.ContainsKey(key);
        }

        public bool TryGetValue(string key, out StringValues value)
        {
            return _queryCollection.TryGetValue(key, out value);
        }

        public StringValues this[string key] =>
            _queryCollection[key];

        public IEnumerable<string> Keys =>
            _queryCollection.Keys;

        public IEnumerable<StringValues> Values =>
            throw new NotImplementedException();
    }
}
