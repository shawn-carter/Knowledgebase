console.log("Loaded Custom JS File");

// Toolbar Options for Quill.js
const ToolbarOptions = [
  ["bold", "italic", "underline", "strike"], // Text formatting options
  [{ list: "ordered" }, { list: "bullet" }], // List options
  [{ size: [false, "large"] }], // Font size
  [{ indent: "-1" }, { indent: "+1" }], // Indentation options
  [{ font: [] }], // Font family
  [{ align: [] }], // Text alignment
  ["link", "image", "video"], // Additional options like link, image, and video
  ["clean"], // Remove formatting option
];

// Function to add a metatag to the list of selected tags
function addMetatagToSelected(tag, selectedMetatags,meta_data_input) {
  if (!tag || !tag.trim()) return; // Check if tag is empty or just spaces

  // Get existing tags using jQuery
  let existingTags = selectedMetatags
    .children()
    .map(function () {
      return $(this).text();
    })
    .get();

  if (existingTags.includes(tag)) {
    console.log(`Tag "${tag}" is already added.`);
    return;
  }

  // Create a new button using jQuery
  let tagButton = $("<button>")
    .attr("type", "button")
    .text(tag)
    .addClass("btn btn-secondary m-1")
    .click(function () {
      console.log("Attempting to remove tag:", $(this).text());
      $(this).remove();
      updateMetaDataInput(selectedMetatags,meta_data_input);
    });

  selectedMetatags.append(tagButton);

  console.log("Updated number of tags:", selectedMetatags.children().length);
  updateMetaDataInput(selectedMetatags,meta_data_input); // Update the hidden input after adding a tag
}

// Function to update the value of the hidden meta_data_input
function updateMetaDataInput(selectedMetatags,meta_data_input) {
    console.log(selectedMetatags);
  // Get selected tags using jQuery
  let selectedTags = selectedMetatags
    .children()
    .map(function () {
      return $(this).text();
    })
    .get();
  console.log("Selected tags array:", selectedTags);
  meta_data_input.val(selectedTags.join(",")); // Set value using jQuery
  console.log("Updated hidden input with tags:", meta_data_input.val());
}
