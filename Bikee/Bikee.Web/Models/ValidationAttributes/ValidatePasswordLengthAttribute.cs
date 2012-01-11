using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Web.Mvc;
using System.Web.Security;

namespace Bikee.Web.Models.ValidationAttributes
{
	[AttributeUsage(AttributeTargets.Field | AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
	public sealed class ValidatePasswordLengthAttribute : ValidationAttribute, IClientValidatable
	{
		private static readonly string DefaultErrorMessage = "'{0}' must be at least {1} characters long.";
		private readonly int minCharacters = Membership.Provider.MinRequiredPasswordLength;

		public ValidatePasswordLengthAttribute(): base(DefaultErrorMessage)
		{
		}

		public override string FormatErrorMessage(string name)
		{
			return String.Format(CultureInfo.CurrentCulture, ErrorMessageString, name, this.minCharacters);
		}

		public override bool IsValid(object value)
		{
			var valueAsString = value as string;
			return (valueAsString != null && valueAsString.Length >= this.minCharacters);
		}

		public IEnumerable<ModelClientValidationRule> GetClientValidationRules(ModelMetadata metadata, ControllerContext context)
		{
			return new[]
								{
									new ModelClientValidationStringLengthRule(FormatErrorMessage(metadata.GetDisplayName()), this.minCharacters, int.MaxValue)
								};
		}
	}
}