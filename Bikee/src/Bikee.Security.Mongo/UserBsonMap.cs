using Bikee.Bson;
using Bikee.Security.Domain;

namespace Bikee.Security.Mongo
{
	public class UserBsonMap : BsonMap<User>
	{
		public UserBsonMap()
		{
		}
	}
}