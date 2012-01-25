using System;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.IdGenerators;

namespace Bikee.Bson
{
	public abstract class BsonMap<T>
	{
		protected BsonMap()
		{
			if (!BsonClassMap.IsClassMapRegistered(typeof(T)))
			{
				BsonClassMap.RegisterClassMap<T>(cm =>
				{
					cm.AutoMap();
					//cm.IdMemberMap.SetIdGenerator(BsonObjectIdGenerator.Instance);
					if (this.Map != null)
					{
						this.Map(cm);
					}
				});
			}
		}

		protected Action<BsonClassMap<T>> Map { private get; set; }
	}
}
