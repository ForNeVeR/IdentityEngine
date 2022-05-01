IdentityEngine
==============
IdentityEngine is a free open source framework for building your own [OpenID Connect 1.0][oidc] provider on top of [OAuth 2.1][oauth-2.1], that adopts the latest security standards.

The project is inspired by [IdentityServer4](https://github.com/IdentityServer/IdentityServer4), developed by [Dominick Baier](https://twitter.com/leastprivilege) and [Brock Allen](https://twitter.com/brocklallen). We are grateful to them for inspiration and their help in developing the open-source .NET ecosystem.

* The implementation only includes the part of OpenID Connect 1.0 protocol that is compatible with OAuth 2.1
* This project is a free alternative to the [IdentityServer4](https://github.com/IdentityServer/IdentityServer4), but not a drop-in replacement
* Designed with extensibility and easy customization in mind

Plans for 1.0
-------------
- [ ] Authorization Code Grant (WIP)
- [ ] Client Credentials Grant
- [ ] Refresh Token Grant
- [ ] Device Authorization Grant
- [ ] OpenID Connect RP-Initiated Logout
- [ ] OpenID Connect Back-Channel Logout
- [ ] SQL-based storage
- [ ] Working example
- [ ] Tests
- [ ] Documentation

Acknowledgements
----------------
IdentityEngine is created using the following wonderful tools:

* [.NET](https://github.com/dotnet/runtime)
* [ASP.NET Core](https://github.com/dotnet/aspnetcore)
* [JetBrains Rider](https://www.jetbrains.com/rider/)

License
-------
IdentityEngine is licensed under [the MIT license](./LICENSE). This is a fundamental position of the project, and will never change in the future.

[oidc]: https://openid.net/specs/openid-connect-core-1_0.html
[oauth-2.1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05
