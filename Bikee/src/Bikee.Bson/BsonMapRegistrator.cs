using System.ComponentModel.Composition;
using System.ComponentModel.Composition.Hosting;

namespace Bikee.Bson
{
	public static class BsonMapRegistrator
	{
		public static void Compose()
		{
			var catalog = new AggregateCatalog(new DirectoryCatalog("."));

			/*
			var dir = new DirectoryInfo(".");

			foreach (var assembly in dir.GetFiles("*.dll").Select(file => Assembly.LoadFile(file.FullName)))
			{
				catalog.Catalogs.Add(new AssemblyCatalog(assembly));
			}
			*/

			var container = new CompositionContainer(catalog);
			container.ComposeParts();

			var maps = container.GetExportedValues<IBsonMap>();

			foreach (var bsonMap in maps)
			{
				bsonMap.Register();
			}
		}
	}
}