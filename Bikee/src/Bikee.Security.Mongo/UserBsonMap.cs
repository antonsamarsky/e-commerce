using System.ComponentModel.Composition;
using Bikee.Bson;
using MongoDB.Bson.Serialization;

namespace Bikee.Security.Mongo
{
	[Export(typeof(IBsonMap))]
	public class UserBsonMap : IBsonMap
	{
		public void Register()
		{
			if (BsonClassMap.IsClassMapRegistered(typeof(User)))
			{
				return;
			}

			BsonClassMap.RegisterClassMap<User>(map =>
			{
				map.AutoMap();
				map.SetIsRootClass(true);
				map.SetIgnoreExtraElements(true);
				map.GetMemberMap(o => o.Roles).SetIgnoreIfNull(true);
			});
		}
	}
}