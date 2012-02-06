using Bikee.Bson;

namespace Bikee.Security.Mongo
{
	public class UserBsonMap : BsonMap<User>
	{
		public UserBsonMap()
		{
			this.Map = cm =>
			{
				cm.SetIsRootClass(true);
				cm.SetIgnoreExtraElements(true);
				cm.GetMemberMap(o => o.Roles).SetIgnoreIfNull(true);
			};
		}
	}
}