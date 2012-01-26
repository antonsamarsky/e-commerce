using System;
using MongoDB.Bson.Serialization;

namespace Bikee.Bson
{
	public abstract class BsonMap<T>
	{
		protected BsonMap()
		{
			if (BsonClassMap.IsClassMapRegistered(typeof(T)))
			{
				return;
			}

			BsonClassMap.RegisterClassMap<T>(cm =>
			{
				cm.AutoMap();
				if (this.Map != null)
				{
					this.Map(cm);
				}
			});
		}

		protected Action<BsonClassMap<T>> Map { private get; set; }
	}
}
