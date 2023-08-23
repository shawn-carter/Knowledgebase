console.log("Loaded Custom JS File from Static");
// If the user navigates to the page using page history or back it will be refreshed
// This prevents cache to show previous states for buttons etc.
// And the rating colour / number of views on all_incidents
if (window.performance.getEntriesByType("navigation")[0].type === "back_forward") {
  location.reload();
}
// Toolbar Options for Quill.js
const ToolbarOptions = [
  ["bold", "italic", "underline", "strike","blockquote","code-block"], // Text formatting options
  [{ list: "ordered" }, { list: "bullet" }], // List options
  [{ size: [false, "large"] }], // Font size
  [{ header: [1,2,3]}], // H1, H2, H3 headings
  [{ color: [] }, { background: [] }], //Colour and Background
  [{ indent: "-1" }, { indent: "+1" }], // Indentation options
  [{ font: [] }], // Font family
  [{ align: [] }], // Text alignment
  ["link", "image", "video"], // Additional options like link, image, and video
  ["clean"], // Remove formatting option
];

// Generic function to set up DataTable on any table - they all use the same id 'table'
function setUpdataTable(options)
{
  let table = new DataTable('#table', options)
}

// This function is to setup the form for the create.html and edit_article.html templates
function initialiseArticleEditor(type) {
  // Initialize Quill editor with custom toolbar options
  var quill = new Quill("#quillEditor", {
    theme: "snow",
    modules: {
      toolbar: ToolbarOptions,
    },
  });

  // Find the quillEditor div and traverse up to its closest parent with class "form-group"
  // We need this to add the 'is-valid' and 'is-invalid classes' as it is created dynamically
  var quillEditorFormGroup = $("#quillEditor").closest(".form-group");
  // Assign an ID to this form-group div
  quillEditorFormGroup.attr("id", "quillEditorFormGroup");
  var formGroup = $("#quillEditorFormGroup");

  // Using jQuery to get the article and title objects
  var article = $("textarea[name=article]");
  var title = $("#id_title");

  // Update the value of the hidden article textarea whenever the Quill content changes
  // Also added some checks as user types and add valid/invalid classes
  quill.on("text-change", function () {
    var text = quill.getText().trim();
    var length = text.length;
    if (length >= 10) {
      formGroup.removeClass("is-invalid").addClass("is-valid");
    } else {
      formGroup.removeClass("is-valid").addClass("is-invalid");
    }
    // Set the article text to the contents of the Quill Editor (including the Quill tags)
    article.val(quill.root.innerHTML);
  });

  // Focus on the Title when we open the editor page we want to focus the title
  // As this is the first user input
  title.focus();

  // Listener for Title (Quick validation on title) on change
  title.on("input", function () {
    var input = $(this);
    var title_length = input.val().length;
    // Must be at least 3 characters or 'is-invalid'
    if (title_length >= 3) {
      input.removeClass("is-invalid").addClass("is-valid");
    } else {
      input.removeClass("is-valid").addClass("is-invalid");
    }
  });

  // References to meta_data_input
  const meta_data_input = $("#meta_data_input");

  // Select the hidden element
  var metatagData = $("#metatagData").attr("data-metatags");
  //console.log("Metatag Data:", metatagData);
  // Read and parse the data attribute

  //const metatags = {{ all_tags_json|safe }}; - the line below replaces this

  const metatags = JSON.parse(metatagData);
  //console.log(metatags);

  // references to the selected items
  const selectedMetatags = $("#selectedMetatags");
  const metatagLookup = $("#metatagLookup");

  // ------------------------------------------------------------------------- This is for existing Articles
  if (type === "edit") {
    var initialMetatagData = $("#initialMetatags").attr("data-metatags")
    const initialMetatags = initialMetatagData.split(',');
    initialMetatags.forEach((tag) => {
      addMetatagToSelected(tag, selectedMetatags, meta_data_input);
    });
  }
  // -------------------------------------------------------------------------------------- End

  // Create and set up the dropdown for metatag lookup using jQuery
  const metatagDropdown = $("<div>").attr("id", "metatagDropdown");
  metatagLookup.after(metatagDropdown);

  // Handle form submission: update hidden input and submit form
  const form = $("#kbEntryForm");
  form.on("submit", function (event) {
    event.preventDefault();
    // Some basic validation to ensure Title and Body are not empty
    var titleText = title.val();
    if (titleText.trim() === "") {
      title.addClass("is-invalid").focus();
      alertify.error("Article Title cannot be blank");
      return false;
    }
    // Title needs to be more than 3 characters
    if (titleText.length < 3) {
      title.focus();
      alertify.error("Article Title should be at least 3 characters");
      return false;
    }
    if (titleText.length > 255) {
      title.focus();
      alertify.error("Article Title should not exceed 255 characters");
      return false;
    }
    // Article cannot be blank
    if (article.val().trim() === "" || article.val() === "<p><br></p>") {
      formGroup.removeClass("is-valid").addClass("is-invalid");
      alertify.error("Article Body cannot be blank");
      //console.log("Article content:"+article.val()); // article will contain <p><br><p> if it is empty
      return false;
    }
    if (stripTags(article.val()).trim().length < 10) {
      formGroup.removeClass("is-valid").addClass("is-invalid");
      alertify.error("Article Body should contain at least 10 characters");
      return false;
    }
    updateMetaDataInput(selectedMetatags, meta_data_input); // Update the hidden input before submitting
    form.off("submit");
    form.submit();
  });

  // Check for validation errors - we needed to do this, as Django was returning the content inside tags...
  // So Testing became <p>Testing</p> - which I think were clean (not real tags - so they were visible)
  if ($(".alert").length > 0) {
    // There are validation errors
    console.log("There is a validation error");

    // Get the original content that was submitted
    var originalContent = $("textarea[name=article]").val();

    // Reset the Quill editor to the original content
    quill.setContents([]);
    quill.clipboard.dangerouslyPasteHTML(originalContent);
  }

  // Handle metatag lookup: show dropdown on keyup, prevent form submission on Enter
  metatagLookup.keydown(function (event) {
    //console.log("Key pressed:", event.key);
    if (event.key === "Enter") {
      event.preventDefault(); // Stop the Enter key from submitting the form

      let value = metatagLookup.val().trim();

      // Check if the value matches any tag in the dropdown
      let dropdownMatches = metatagDropdown
        .children()
        .map(function () {
          return $(this).text().trim();
        })
        .get();

      // If the typed tag matches an existing tag or a dropdown option, add it
      if (
        value &&
        (metatags.includes(value) || dropdownMatches.includes(value))
      ) {
        addMetatagToSelected(value, selectedMetatags, meta_data_input);
      }
      // Otherwise, treat it as a new tag
      else if (value) {
        metatags.push(value); // Add to mock data
        addMetatagToSelected(value, selectedMetatags, meta_data_input);
      }

      metatagDropdown.empty(); // Clear the dropdown
      metatagLookup.val(""); // Clear the input
    }
  });

  metatagLookup.keyup(function (event) {
    if (event.key !== "Enter") {
      // Clear the dropdown first
      metatagDropdown.empty();

      // Filter the metatags based on user input
      let value = metatagLookup.val().trim();
      let matches = metatags.filter((tag) => tag.includes(value));

      // Populate the dropdown with matching tags
      matches.forEach((match) => {
        let tagElement = $("<div>").text(match);
        tagElement.click(function () {
          addMetatagToSelected(match, selectedMetatags, meta_data_input);
          metatagDropdown.empty(); // Clear the dropdown
          metatagLookup.val(""); // Clear the input
          updateMetaDataInput(selectedMetatags, meta_data_input); // Update the hidden input after adding a tag
        });
        metatagDropdown.append(tagElement);
      });
    } else {
      let value = metatagLookup.val().trim();
      if (!metatags.includes(value)) {
        metatags.push(value); // Add to mock data
        addMetatagToSelected(value, selectedMetatags, meta_data_input);
      }
      metatagDropdown.empty(); // Clear the dropdown
      metatagLookup.val(""); // Clear the input
    }
  });
}

// Function to add a metatag to the list of selected tags
function addMetatagToSelected(tag, selectedMetatags, meta_data_input) {
  //console.log("Adding tag:", tag);
  if (!tag || !tag.trim()) return; // Check if tag is empty or just spaces

  // Get existing tags using jQuery
  let existingTags = selectedMetatags
    .children()
    .map(function () {
      return $(this).children(".tag-text").text(); // Only get the text of the tag-text span
    })
    .get();

  if (existingTags.includes(tag)) {
    //console.log(`Tag "${tag}" is already added.`);
    return;
  }

  // Create a new button using jQuery
  let tagButton = $("<button>")
    .attr("type", "button")
    .addClass("btn btn-secondary m-1")
    .click(function () {
      //console.log("Attempting to remove tag:",$(this).children(".tag-text").text()); 
      // Only get the text of the tag-text span
      $(this).remove();
      updateMetaDataInput(selectedMetatags, meta_data_input);
    });

  // Add the tag name and the close icon to the button
  tagButton.append($("<span>").addClass("tag-text").text(tag));
  tagButton.append(
    $("<span>").html("&nbsp;&times;").attr("aria-hidden", "true")
  );

  // Append to the selectedMetatags
  selectedMetatags.append(tagButton);

  //console.log("Updated number of tags:", selectedMetatags.children().length);
  updateMetaDataInput(selectedMetatags, meta_data_input); // Update the hidden input after adding a tag
}

// Function to update the value of the hidden meta_data_input
function updateMetaDataInput(selectedMetatags, meta_data_input) {
  // Get selected tags using jQuery
  let selectedTags = selectedMetatags
    .children()
    .map(function () {
      return $(this).children(".tag-text").text(); // Only get the text of the tag-text span
    })
    .get();
  //console.log("Selected tags array:", selectedTags);
  meta_data_input.val(selectedTags.join(",")); // Set value using jQuery
  //console.log("Setting hidden input with tags:", meta_data_input.val());
}

// Function to strip HTML tags from a string
function stripTags(input) {
  return input.replace(/<\/?[^>]+(>|$)/g, "");
}
