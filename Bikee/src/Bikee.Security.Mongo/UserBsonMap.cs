using Bikee.Bson;
using Bikee.Security.Domain;

namespace Bikee.Security.Mongo
{
	public class UserBsonMap : BsonMap<User>
	{
		public UserBsonMap()
		{
			this.Map = cm => cm.GetMemberMap(o => o.Roles).SetIgnoreIfNull(true);
		}
	}
}