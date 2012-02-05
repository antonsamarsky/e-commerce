using System;
using System.Linq.Expressions;
using System.Reflection;
using MongoDB.Bson.Serialization;

namespace Bikee.Security.Mongo
{
	public class MongoHelper
	{
		public static string GetElementNameFor<TSource>(Expression<Func<TSource, object>> propertyLambda)
		{
			return GetElementNameFor<TSource, object>(propertyLambda);
		}

		/// <summary>
		/// Reference:
		/// http://stackoverflow.com/questions/671968/retrieving-property-name-from-lambda-expression
		/// </summary>
		public static string GetElementNameFor<TSource, TProperty>(Expression<Func<TSource, TProperty>> propertyLambda)
		{
			Type type = typeof(TSource);

			var member = propertyLambda.Body as MemberExpression;
			if (member == null)
			{
				throw new ArgumentException(string.Format("Expression '{0}' refers to a method, not a property.", propertyLambda));
			}

			var propInfo = member.Member as PropertyInfo;
			if (propInfo == null)
			{
				throw new ArgumentException(string.Format("Expression '{0}' refers to a field, not a property.", propertyLambda));
			}

			if (type != propInfo.ReflectedType && !type.IsSubclassOf(propInfo.ReflectedType))
			{
				throw new ArgumentException(string.Format("Expresion '{0}' refers to a property that is not from type {1}.", propertyLambda, type));
			}

			var map = BsonClassMap.LookupClassMap(typeof(TSource));
			if (map == null)
			{
				throw new ArgumentException(string.Format("Missing BsonClassMap for type {0}", type));
			}

			var memberMap = map.GetMemberMap(propInfo.Name);
			if (null == memberMap)
			{
				throw new ArgumentException(string.Format("BsonClassMap for type {0} does not contain a mapping for member {1}", type, propInfo.Name));
			}

			return memberMap.ElementName;
		}
	}
}